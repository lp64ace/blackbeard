#include "manualmap.h"

#include "mom.h"
#include "intern/mom_internal.h"

#include <stdio.h>
#include <string.h>

#define LOWORD_UINT32(x) ((uint16_t)((x) & 0xFFFF))
#define HIWORD_UINT32(x) ((uint16_t)(((x) >> 16) & 0xFFFF))

/* -------------------------------------------------------------------- */
/** \name Implementation
 * \{ */

// TODO Slow as fuck! Hopefully we can fix that at some point!
void *BOB_manual_map_resolve_import(ProcessHandle *process, const char *libname, const char *expname, int maxhops) {
	ModuleHandle *handle = NULL;
	
	do {
		if ((handle = MOM_module_open_by_name(process, libname))) {
			break;
		}
		if ((handle = MOM_module_open_by_file(libname))) {
			break;
		}

		/**
		 * We tried to find the module in an already loaded memory address... we failed!
		 * We tried to find the modile in the disk... we failed!
		 * 
		 * Oh well...!
		 */
		return NULL;
	} while (false);

	void *address = NULL;

	for (ModuleHandle *itr = handle; itr; itr = MOM_module_next(itr)) {
		ModuleHandle *existing = NULL;

		/**
		 * TODO I do not like this system, having to first load the module, 
		 * then looking to find it within the loaded modules is bad!
		 */

		// We have already loaded this module as a depdency, resolve it!
		if ((existing = MOM_process_module_find(process, handle))) {
			ModuleExport *exported = NULL;

			if (((uintptr_t)expname & ~0xFFFF) != 0) {
				exported = MOM_module_export_find_by_name(existing, expname);
			} else {
				exported = MOM_module_export_find_by_ordinal(existing, POINTER_AS_INT(expname));
			}

			// The export we are looking for exists but it is a forwarded export!
			if (MOM_module_export_lib(existing, exported)) {
				if (MOM_module_export_forward_name(existing, exported)) {
					MOM_module_close_collection(handle);
					return BOB_manual_map_resolve_import(process, MOM_module_export_lib(existing, exported), MOM_module_export_forward_name(existing, exported), maxhops - 1);
				} else {
					MOM_module_close_collection(handle);
					return BOB_manual_map_resolve_import(process, MOM_module_export_lib(existing, exported), POINTER_FROM_INT(MOM_module_export_forward_ordinal(existing, exported)), maxhops - 1);
				}
			}

			if (exported) {
				MOM_module_close_collection(handle);

				// The export we are looking for exists and is a normal export!
				return MOM_module_export_memory(existing, exported);
			}
		}

		// We haven't loaded this module, check if the module contains the export we are looking for!
		ModuleExport *exported = NULL;

		if (((uintptr_t)expname & ~0xFFFF) != 0) {
			exported = MOM_module_export_find_by_name(handle, expname);
		} else {
			exported = MOM_module_export_find_by_ordinal(handle, POINTER_AS_INT(expname));
		}

		if (exported) {
			// Try to manual map the module into the process as well so that we can resolve the export!
			if (BOB_manual_map_module(process, handle, 0)) {
				MOM_module_close_collection(handle);

				// The next time we call this #BOB_manual_map_module must have updated the loaded modules to find this one!
				return BOB_manual_map_resolve_import(process, libname, expname, maxhops - 1);
			}
		}
	}

	MOM_module_close_collection(handle);
	return NULL;
}

void *BOB_manual_map_module(ProcessHandle *process, ModuleHandle *handle, int flag) {
	ModuleHandle *existing = NULL;
	if ((existing = MOM_process_module_find(process, handle))) {
		return existing->real;
	}

	size_t size = MOM_module_memory_size(handle);

	void *base = ((flag & kBobRebaseAlways) == 0) ? (void *)handle->base : NULL;

	void *real = NULL;
	if (!(real = (uintptr_t)MOM_process_allocate(process, base, size, kMomProtectRead | kMomProtectWrite | kMomProtectExec))) {
		// The PE has a base address that likes to be mapped to, but if relocation data are present we can map it elsewhere!
		if (!(real = (uintptr_t)MOM_process_allocate(process, NULL, size, kMomProtectRead | kMomProtectWrite | kMomProtectExec))) {
			MOM_module_close(handle);
			return NULL;
		}
	}

	handle->real = (uintptr_t)real;

	fprintf(stdout, "[BOB] module %s address : 0x%p\n", MOM_module_name(handle) ? MOM_module_name(handle) : "(null)", real);

	/**
	 * Sections need to be mapped into the memory we allocate in the remote process in order to write the data from file!
	 * \note Protection needs to be updated as well so that some sections are read-only or executable! (Below)
	 */

	for (ModuleSection *section = MOM_module_section_begin(handle); section != MOM_module_section_end(handle); section = MOM_module_section_next(handle, section)) {
		if (!MOM_process_write(process, MOM_module_section_memory(handle, section), MOM_module_section_disk(handle, section), MOM_module_section_size(handle, section))) {
			fprintf(stderr, "[BOB] Failed to copy section %s.\n", MOM_module_section_name(handle, section));
			MOM_module_close(handle);
			return NULL;
		}
	}

	/**
	 * Imports are basically addresses that store pointers to function in other modules.
	 * These needs to be resolved so that the ASM can call them like;
	 * 
	 * \code{.asm}
	 * mov r13 qword ptr [address]
	 * call r13
	 * \endcode
	 * 
	 * The imports especially on windows are a mess, we need to follow imports to different modules, etc...!
	 */

	for (ModuleImport *import = MOM_module_import_begin(handle); import != MOM_module_import_end(handle); import = MOM_module_import_next(handle, import)) {
		void *address = NULL;

		if (MOM_module_import_name(handle, import)) {
			address = BOB_manual_map_resolve_import(process, MOM_module_import_lib(handle, import), MOM_module_import_name(handle, import), 8);
		} else {
			address = BOB_manual_map_resolve_import(process, MOM_module_import_lib(handle, import), POINTER_FROM_INT(MOM_module_import_ordinal(handle, import)), 8);
		}

		if (MOM_module_import_name(handle, import)) {
			fprintf(stdout, "[BOB] %s import 0x%p %s\n", (address) ? "OK" : "WARN", address, MOM_module_import_name(handle, import));
		} else {
			fprintf(stdout, "[BOB] %s import 0x%p #%d\n", (address) ? "OK" : "WARN", address, MOM_module_import_ordinal(handle, import));
		}

		size_t ptrsize = MOM_module_architecture_pointer_size(MOM_module_architecture(handle));

		/**
		 * There are imports like #QueryOOBESupport from kernel32.dll that on some platforms are non-existing!
		 * These are not reasons to fail the procedure, ignore these imports...
		 */
		if (address) {
			if (!MOM_process_write(process, MOM_module_import_to_memory(handle, import), &address, ptrsize)) {
				fprintf(stderr, "[BOB] Failed to copy import to address 0x%p.\n", MOM_module_import_to_memory(handle, import));
				MOM_module_close(handle);
				return NULL;
			}
		}
	}
	for (ModuleImport *import = MOM_module_import_delayed_begin(handle); import != MOM_module_import_delayed_end(handle); import = MOM_module_import_delayed_next(handle, import)) {
		void *address = NULL;

		if (MOM_module_import_name(handle, import)) {
			address = BOB_manual_map_resolve_import(process, MOM_module_import_lib(handle, import), MOM_module_import_name(handle, import), 8);
		} else {
			address = BOB_manual_map_resolve_import(process, MOM_module_import_lib(handle, import), POINTER_FROM_INT(MOM_module_import_ordinal(handle, import)), 8);
		}

		if (MOM_module_import_name(handle, import)) {
			fprintf(stdout, "[BOB] %s delayed import %s\n", (address) ? "OK" : "WARN", MOM_module_import_name(handle, import));
		} else {
			fprintf(stdout, "[BOB] %s delayed import #%d\n", (address) ? "OK" : "WARN", MOM_module_import_ordinal(handle, import));
		}

		size_t ptrsize = MOM_module_architecture_pointer_size(MOM_module_architecture(handle));

		/**
		 * There are imports like #QueryOOBESupport from kernel32.dll that on some platforms are non-existing!
		 * These are not reasons to fail the procedure, ignore these imports...
		 */
		if (address) {
			if (!MOM_process_write(process, MOM_module_import_to_memory(handle, import), &address, ptrsize)) {
				fprintf(stderr, "[BOB] Failed to copy delayed import to address 0x%p.\n", MOM_module_import_to_memory(handle, import));
				MOM_module_close(handle);
				return NULL;
			}
		}
	}

	/**
	 * Relocations are absolute addresses within the module, these usually reference static variable blocks.
	 * These are the reason we use ? on pattern matching when creating signatures for functions!
	 * 
	 * and relative addressess but that is a different story...!
	 */

	ptrdiff_t delta = handle->real - handle->base;

	bool relocations = true;
	for (ModuleRelocation *relocation = MOM_module_relocation_begin(handle); relocation != MOM_module_relocation_end(handle); relocation = MOM_module_relocation_next(handle, relocation)) {
		switch (MOM_module_relocation_type(handle, relocation)) {
			case kMomRelocationHigh: {
				uint16_t *raw = (uint16_t *)MOM_module_relocation_memory(handle, relocation);
				
				uint16_t value;
				if (!MOM_process_read(process, raw, &value, sizeof(value))) {
					fprintf(stderr, "[BOB] Failed to read previous value of relocation at 0x%p.\n", raw);
					relocations &= false;
				}

				fprintf(stdout, "[BOB] relocate HIGH  FROM 0x%p TO ", (void *)value);
				value += HIWORD_UINT32(delta);
				fprintf(stdout, "0x%p\n", (void *)value);

				if (!MOM_process_write(process, raw, &value, sizeof(value))) {
					fprintf(stderr, "[BOB] Failed to write new value of relocation at 0x%p.\n", raw);
					relocations &= false;
				}
			} break;
			case kMomRelocationLow: {
				uint16_t *raw = (uint16_t *)MOM_module_relocation_memory(handle, relocation);

				uint16_t value;
				if (!MOM_process_read(process, raw, &value, sizeof(value))) {
					fprintf(stderr, "[BOB] Failed to read previous value of relocation at 0x%p.\n", raw);
					relocations &= false;
				}

				fprintf(stdout, "[BOB] relocate LOW   FROM 0x%p TO ", (void *)value);
				value += LOWORD_UINT32(delta);
				fprintf(stdout, "0x%p\n", (void *)value);

				if (!MOM_process_write(process, raw, &value, sizeof(value))) {
					fprintf(stderr, "[BOB] Failed to write new value of relocation at 0x%p.\n", raw);
					relocations &= false;
				}
			} break;
			case kMomRelocationHighLow: {
				uint32_t *raw = (uint32_t *)MOM_module_relocation_memory(handle, relocation);

				uint32_t value;
				if (!MOM_process_read(process, raw, &value, sizeof(value))) {
					fprintf(stderr, "[BOB] Failed to read previous value of relocation at 0x%p.\n", raw);
					relocations &= false;
				}

				fprintf(stdout, "[BOB] relocate HILOW FROM 0x%p TO ", (void *)value);
				value += delta;
				fprintf(stdout, "0x%p\n", (void *)value);

				if (!MOM_process_write(process, raw, &value, sizeof(value))) {
					fprintf(stderr, "[BOB] Failed to write new value of relocation at 0x%p.\n", raw);
					relocations &= false;
				}
			} break;
			case kMomRelocationDir64: {
				uint64_t *raw = (uint64_t *)MOM_module_relocation_memory(handle, relocation);

				uint64_t value;
				if (!MOM_process_read(process, raw, &value, sizeof(value))) {
					fprintf(stderr, "[BOB] Failed to read previous value of relocation at 0x%p.\n", raw);
					relocations &= false;
				}

				fprintf(stdout, "[BOB] relocate DIR64 FROM 0x%p TO ", (void *)value);
				value += delta;
				fprintf(stdout, "0x%p\n", (void *)value);

				if (!MOM_process_write(process, raw, &value, sizeof(value))) {
					fprintf(stderr, "[BOB] Failed to write new value of relocation at 0x%p.\n", raw);
					relocations &= false;
				}
			} break;
		}
	}

	if (!relocations) {
		MOM_module_close(handle);
		return NULL;
	}

	for (ModuleSection *section = MOM_module_section_begin(handle); section != MOM_module_section_end(handle); section = MOM_module_section_next(handle, section)) {
		if (!MOM_process_protect(process, MOM_module_section_memory(handle, section), MOM_module_section_size(handle, section), MOM_module_section_protect(handle, section))) {
			fprintf(stderr, "[BOB] Failed to protection section %s.\n", MOM_module_section_name(handle, section));
			MOM_module_close(handle);
			return NULL;
		}
	}

	MOM_process_module_push(process, handle);
	return real;
}

void *BOB_manual_map_image(ProcessHandle *process, const void *image, size_t size, int flag) {
	ModuleHandle *handle = MOM_module_open_by_image(image, size);

	void *real = NULL;
	if ((real = BOB_manual_map_module(process, handle, flag))) {
		// Nothing to do!
	}

	MOM_module_close(handle);
	return real;
}

/** \} */
