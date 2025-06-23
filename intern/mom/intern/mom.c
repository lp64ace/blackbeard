/*
 * MIT License
 *
 * Copyright (c) 2024 dmpokisk
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include "mom_internal.h"
#include "mom.h"

/* -------------------------------------------------------------------- */
/** \name Architecture
 * { */

/* clang-format off */

size_t MOM_module_architecture_pointer_size(eMomArchitecture architecture) {
	switch (architecture) {
		case kMomArchitectureAmd32: return sizeof(int32_t);
		case kMomArchitectureAmd64: return sizeof(int64_t);
	}
	return 0;
}

/* clang-format on */

/** \} */

/* -------------------------------------------------------------------- */
/** \name Module
 * { */

const char *mom_module_name(const ModuleHandle *handle) {
	return (handle->dllname[0]) ? handle->dllname : NULL;
}

void *mom_module_set_address(ModuleHandle *handle, void *address) {
	// This should not be changed for already loaded by address modules!
	// assert(!handle->real);

	/**
	 * This is used to retrieve the physical address of virtual addresses!
	 */
	if (!handle->real) {
		handle->real = (uintptr_t)address;
	}

	return (void *)handle->real;
}

void *mom_module_get_address(ModuleHandle *handle) {
	return (void *)handle->real;
}

void *mom_module_get_base(ModuleHandle *handle) {
	return (void *)handle->base;
}

void mom_module_close_collection(ListBase *collection) {
	LISTBASE_FOREACH_MUTABLE(ModuleHandle *, module, collection) {
		MOM_module_close(module);
	}
}

ListBase mom_module_sections(ModuleHandle *handle) {
	return handle->sections;
}

ListBase mom_module_exports(ModuleHandle *handle) {
	return handle->exports;
}

ListBase mom_module_imports(ModuleHandle *handle) {
	return handle->imports;
}

ListBase mom_module_imports_delayed(ModuleHandle *handle) {
	return handle->imports_delayed;
}

ListBase mom_module_tls(ModuleHandle *handle) {
	return handle->tls;
}

ListBase mom_module_relocations(ModuleHandle *handle) {
	return handle->relocations;
}

const char *mom_module_export_name(ModuleHandle *handle, ModuleExport *exported) {
	return (exported->expname[0]) ? exported->expname : NULL;
}

short mom_module_export_ordinal(ModuleHandle *handle, ModuleExport *exported) {
	return (MOM_module_export_is_ordinal(handle, exported)) ? exported->ordinal : -1;
}

bool mom_module_export_is_ordinal(ModuleHandle *handle, ModuleExport *exported) {
	// If there is no export name then this is export by ordinal!
	return (exported->expname[0] == '\0') ? true : false;
}

bool mom_module_export_is_forward(ModuleHandle *handle, ModuleExport *exported) {
	return (exported->libname[0]) ? true : false;
}

bool mom_module_export_is_forward_by_ordinal(ModuleHandle *handle, ModuleExport *exported) {
	if (MOM_module_export_is_forward(handle, exported)) {
		// If there is no forward name then this is forward by ordinal!
		return (exported->fwdname[0] == '\0') ? true : false;
	}
	return false;
}

const char *mom_module_export_forward_libname(ModuleHandle *handle, ModuleExport *exported) {
	return (exported->libname[0]) ? exported->libname : NULL;
}

short mom_module_export_forward_ordinal(ModuleHandle *handle, ModuleExport *exported) {
	if (MOM_module_export_is_fowrard_by_ordinal(handle, exported)) {
		return exported->fwdordinal;
	}
	return -1;
}

const char *mom_module_export_forward_name(ModuleHandle *handle, ModuleExport *exported) {
	if (MOM_module_export_is_forward(handle, exported)) {
		return (exported->fwdname[0]) ? exported->fwdname : NULL;
	}
	return NULL;
}

bool mom_module_import_is_ordinal(ModuleHandle *handle, ModuleImport *imported) {
	return (imported->expname[0] == '\0') ? true : false;
}

const char *mom_module_import_libname(ModuleHandle *handle, ModuleImport *imported) {
	return imported->libname;
}

const char *mom_module_import_expname(ModuleHandle *handle, ModuleImport *imported) {
	return (imported->expname[0]) ? imported->expname : NULL;
}

short mom_module_import_expordinal(ModuleHandle *handle, ModuleImport *imported) {
	return imported->expordinal;
}

eMomRelocationType mom_module_relocation_type(ModuleHandle *handle, ModuleRelocation *relocation) {
	return relocation->type;
}

/** \} */

/* -------------------------------------------------------------------- */
/** \name Process
 * { */

void mom_process_close_collection(ListBase *collection) {
	LISTBASE_FOREACH_MUTABLE(ProcessHandle *, process, collection) {
		MOM_process_close(process);
	}
}

/** \} */

/* -------------------------------------------------------------------- */
/** \name Exports
 * { */

fnMOM_module_name MOM_module_name = mom_module_name;
fnMOM_module_set_address MOM_module_set_address = mom_module_set_address;
fnMOM_module_get_address MOM_module_get_address = mom_module_get_address;
fnMOM_module_get_base MOM_module_get_base = mom_module_get_base;

fnMOM_module_close_collection MOM_module_close_collection = mom_module_close_collection;
fnMOM_module_sections MOM_module_sections = mom_module_sections;
fnMOM_module_exports MOM_module_exports = mom_module_exports;
fnMOM_module_imports MOM_module_imports = mom_module_imports;
fnMOM_module_imports_delayed MOM_module_imports_delayed = mom_module_imports_delayed;
fnMOM_module_tls MOM_module_tls = mom_module_tls;
fnMOM_module_relocations MOM_module_relocations = mom_module_relocations;

fnMOM_module_export_name MOM_module_export_name = mom_module_export_name;
fnMOM_module_export_ordinal MOM_module_export_ordinal = mom_module_export_ordinal;
fnMOM_module_export_is_ordinal MOM_module_export_is_ordinal = mom_module_export_is_ordinal;
fnMOM_module_export_is_forward MOM_module_export_is_forward = mom_module_export_is_forward;
fnMOM_module_export_is_fowrard_by_ordinal MOM_module_export_is_fowrard_by_ordinal = mom_module_export_is_forward_by_ordinal;
fnMOM_module_export_forward_libname MOM_module_export_forward_libname = mom_module_export_forward_libname;
fnMOM_module_export_forward_ordinal MOM_module_export_forward_ordinal = mom_module_export_forward_ordinal;
fnMOM_module_export_forward_name MOM_module_export_forward_name = mom_module_export_forward_name;

ModuleExport *MOM_module_export_find_by_name(ModuleHandle *handle, const char *name) {
	LISTBASE_FOREACH(ModuleExport *, exported, &handle->exports) {
		if (!MOM_module_export_is_ordinal(handle, exported)) {
			if (strcmp(MOM_module_export_name(handle, exported), name) == 0) {
				return exported;
			}
		}
	}
	return NULL;
}

ModuleExport *MOM_module_export_find_by_ordinal(ModuleHandle *handle, short ordinal) {
	LISTBASE_FOREACH(ModuleExport *, exported, &handle->exports) {
		if (MOM_module_export_is_ordinal(handle, exported)) {
			if (MOM_module_export_ordinal(handle, exported) == ordinal) {
				return exported;
			}
		}
	}
	return NULL;
}

fnMOM_module_import_is_ordinal MOM_module_import_is_ordinal = mom_module_import_is_ordinal;
fnMOM_module_import_libname MOM_module_import_libname = mom_module_import_libname;
fnMOM_module_import_expname MOM_module_import_expname = mom_module_import_expname;
fnMOM_module_import_expordinal MOM_module_import_expordinal = mom_module_import_expordinal;

fnMOM_module_relocation_type MOM_module_relocation_type = mom_module_relocation_type;

fnMOM_process_close_collection MOM_process_close_collection = mom_process_close_collection;

/** \} */
