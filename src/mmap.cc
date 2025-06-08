#include "config.h"
#include "mmap.h"
#include "mod.h"
#include "native.h"
#include "thread.h"
#include "remote.h"
#include "spoof.h"
#include "proc.h"

#include "xorstr.hh"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <tchar.h>

/* -------------------------------------------------------------------- */
/** \name Internal
 * \{ */

template<typename T> struct ManualMapArch;

template<> struct ManualMapArch<uint32_t> {
	const IMAGE_NT_HEADERS32 *nt;

	IMAGE_THUNK_DATA32 *thunk;
	IMAGE_THUNK_DATA32 *func;
	const IMAGE_TLS_DIRECTORY32 *tls;
};

template<> struct ManualMapArch<uint64_t> {
	const IMAGE_NT_HEADERS64 *nt;

	IMAGE_THUNK_DATA64 *thunk;
	IMAGE_THUNK_DATA64 *func;
	const IMAGE_TLS_DIRECTORY64 *tls;
};

template<typename T = uintptr_t> struct ManualMap : public ManualMapArch<T> {
	const IMAGE_DOS_HEADER *dos;
	T base;
	T size;

	BobProc *process;
	BobRemote *worker;
	TCHAR temp[MAX_PATH];
	HANDLE actctx;

	void *source;
	const void *manifest;
	const void *remote;

	const IMAGE_SECTION_HEADER *begin() const {
		return static_cast<const IMAGE_SECTION_HEADER *>(IMAGE_FIRST_SECTION(this->nt));
	}
	const IMAGE_SECTION_HEADER *end() const {
		return static_cast<const IMAGE_SECTION_HEADER *>(IMAGE_FIRST_SECTION(this->nt) + this->nt->FileHeader.NumberOfSections);
	}

	bool is64() const {
		return this->nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC;
	}
	bool is32() const {
		return this->nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC;
	}
};

template<typename T = uintptr_t> BOB_STATIC bool bob_mmap_init(ManualMap<T> *self, BobProc *process, const void *image, size_t size) {
	self->source = BOB_ALLOC(size);
	memcpy(self->source, image, size);
	self->dos = static_cast<decltype(self->dos)>(self->source);
	self->nt = static_cast<decltype(self->nt)>(POINTER_OFFSET(self->dos, self->dos->e_lfanew));

	self->base = static_cast<T>(self->nt->OptionalHeader.ImageBase);
	self->size = static_cast<T>(self->nt->OptionalHeader.SizeOfImage);

	self->process = process;
	if (self->nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].Size) {
		BOB_DEBUG_PRINT(stderr, XORSTR("[ERR] Image contains COM, manual mapping is not supported for managed executables!"));
		return false;
	}

	uint64_t lo = 0x7FFFFFFFFFFFFFFF;
	uint64_t hi = 0x0000000000000000;
	for (auto section = self->begin(); section < self->end(); section++) {
		lo = min(lo, section->VirtualAddress);
		hi = max(hi, section->VirtualAddress + section->Misc.VirtualSize);
	}

	self->size = static_cast<T>(hi - lo);
	if (!(self->remote = BOB_process_alloc(self->process, reinterpret_cast<void *>(self->base), self->size, PROTECT_R | PROTECT_W | PROTECT_E))) {
		if (!(self->remote = BOB_process_alloc(self->process, NULL, self->size, PROTECT_R | PROTECT_W | PROTECT_E))) {
			return false;
		}
	}

	if (!(self->worker = BOB_remote_open(self->process, self->is64()))) {
		BOB_DEBUG_PRINT(stderr, XORSTR("[ERR] Failed to create remote environment!"));
		return false;
	}

	return true;
}

enum {
	ADDRESS_RVA,
	ADDRESS_VA,
	ADDRESS_RPA,
};

template<typename T = uintptr_t> BOB_STATIC void *bob_mmap_resolve_rva(ManualMap<T> *self, uintptr_t rva, const void *base, int type) {
	switch (type) {
		case ADDRESS_RVA: {
			return reinterpret_cast<void *>(rva);
		} break;
		case ADDRESS_VA:
		case ADDRESS_RPA: {
			for (IMAGE_SECTION_HEADER *section = IMAGE_FIRST_SECTION(self->nt); section != IMAGE_FIRST_SECTION(self->nt) + self->nt->FileHeader.NumberOfSections; section++) {
				if (rva >= section->VirtualAddress && rva < section->VirtualAddress + section->Misc.VirtualSize) {
					if (type == ADDRESS_VA) {
						return POINTER_OFFSET(base, rva - section->VirtualAddress + section->PointerToRawData);
					}
					else {
						return POINTER_OFFSET(rva, section->VirtualAddress + section->PointerToRawData);
					}
				}
			}
		} break;
	}
	return NULL;
}

template<typename T = uintptr_t> BOB_STATIC const void *bob_mmap_directory(ManualMap<T> *self, const void *base, int directory) {
	const IMAGE_DATA_DIRECTORY *image = &self->nt->OptionalHeader.DataDirectory[directory];
	if (!image->VirtualAddress || !image->Size) {
		return NULL;
	}
	return bob_mmap_resolve_rva(self, image->VirtualAddress, base, ADDRESS_VA);
}

template<typename T = uintptr_t> BOB_STATIC size_t bob_mmap_directory_size(ManualMap<T> *self, const void *base, int directory) {
	const IMAGE_DATA_DIRECTORY *image = &self->nt->OptionalHeader.DataDirectory[directory];
	if (!image->VirtualAddress || !image->Size) {
		return NULL;
	}
	return image->Size;
}

template<typename T = uintptr_t> BOB_STATIC const void *bob_mmap_manifest(ManualMap<T> *self, int *r_manifest, int *r_size) {
	const IMAGE_RESOURCE_DIRECTORY_ENTRY *node[3] = {NULL, NULL, NULL};
	const IMAGE_RESOURCE_DIRECTORY *node_ptr[2] = {NULL, NULL};
	const IMAGE_RESOURCE_DATA_ENTRY *node_data[1] = {NULL};

	size_t offset[3] = {0, 0, 0};

	const void *base = bob_mmap_directory(self, self->source, IMAGE_DIRECTORY_ENTRY_RESOURCE);
	if (!base) {
		return NULL;
	}

	node_ptr[0] = (const IMAGE_RESOURCE_DIRECTORY *)base;
	offset[0] += sizeof(IMAGE_RESOURCE_DIRECTORY);

	for (int i = 0; i < node_ptr[0]->NumberOfIdEntries + node_ptr[0]->NumberOfNamedEntries; i++) {
		node[0] = (const IMAGE_RESOURCE_DIRECTORY_ENTRY *)POINTER_OFFSET(base, offset[0]);
		if (!node[0]->DataIsDirectory || node[0]->Id != 0x18) {
			offset[0] += sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY);
			continue;
		}
		node_ptr[1] = (const IMAGE_RESOURCE_DIRECTORY *)POINTER_OFFSET(base, node[0]->OffsetToDirectory);
		offset[1] = node[0]->OffsetToDirectory + sizeof(IMAGE_RESOURCE_DIRECTORY);

		for (int j = 0; j < node_ptr[1]->NumberOfIdEntries + node_ptr[1]->NumberOfNamedEntries; j++) {
			node[1] = (const IMAGE_RESOURCE_DIRECTORY_ENTRY *)POINTER_OFFSET(base, offset[1]);
			if (!node[1]->DataIsDirectory) {
				offset[1] += sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY);
				continue;
			}

			if (node[1]->Id == 1 || node[1]->Id == 2 || node[1]->Id == 3) {
				offset[2] = node[1]->OffsetToDirectory + sizeof(IMAGE_RESOURCE_DIRECTORY);
				node[2] = (const IMAGE_RESOURCE_DIRECTORY_ENTRY *)POINTER_OFFSET(base, offset[2]);
				node_data[0] = (const IMAGE_RESOURCE_DATA_ENTRY *)POINTER_OFFSET(base, node[2]->OffsetToData);

				if (r_manifest) {
					*r_manifest = node[1]->Id;
				}
				if (r_size) {
					*r_size = node_data[0]->Size;
				}

				return bob_mmap_resolve_rva(self, node_data[0]->OffsetToData, self->source, ADDRESS_VA);
			}

			offset[1] += sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY);
		}
		offset[0] += sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY);
	}

	return NULL;
}

template<typename T = uintptr_t> BOB_STATIC TCHAR *bob_mmap_manifest_write(ManualMap<T> *self) {
	int resource, size;
	if (!(self->manifest = bob_mmap_manifest(self, &resource, &size))) {
		return NULL;
	}
	
	TCHAR directory[MAX_PATH];
	GetTempPath(ARRAYSIZE(directory), directory);
	if (GetTempFileName(directory, _T("ImageManifest"), 0, self->temp) == 0) {
		return NULL;
	}
	HANDLE file = (HANDLE)SPOOF(NULL, CreateFile, self->temp, FILE_GENERIC_WRITE, 0, NULL, OPEN_ALWAYS, 0, NULL);
	if (file) {
		DWORD bytes = 0;
		WriteFile(file, self->manifest, size, &bytes, NULL);
		CloseHandle(file);
		return self->temp;
	}
	return NULL;
}

template<typename T = uintptr_t> BOB_STATIC bool bob_mmap_actx(ManualMap<T> *self) {
	if (!bob_mmap_manifest_write(self)) {
		return false;
	}

	ACTCTX context;
	memset(&context, 0, sizeof(ACTCTX));
	context.cbSize = sizeof(ACTCTX);
	context.lpSource = static_cast<LPCSTR>(BOB_remote_write(self->worker, self->temp, sizeof(self->temp)));

	BobModule *kernel32 = BOB_module_open(self->process, XORSTR("kernel32.dll"), SEARCH_DEFAULT);
	decltype(&CreateActCtx) _CreateActCtx = static_cast<decltype(&CreateActCtx)>(BOB_module_export(self->process, kernel32, XORSTR(STRINGIFY_DEFINE(CreateActCtx))));

	BOB_remote_begin_call64(self->worker);

	BOB_remote_push(self->worker, &context, sizeof(ACTCTX));
	BOB_remote_call(self->worker, REMOTE_WIN64, _CreateActCtx);
	BOB_remote_save(self->worker, 0);
	BOB_remote_notify(self->worker);

	BOB_remote_end_call64(self->worker);

	if (!(self->actctx = reinterpret_cast<HANDLE>(BOB_remote_exec(self->worker, NULL)))) {
		return false;
	}

	return self->actctx != INVALID_HANDLE_VALUE;
}

template<typename T = uintptr_t> BOB_STATIC bool bob_mmap_dependency_ex(ManualMap<T> *self, const WCHAR *path) {
	using fnLdrLoadDll = NTSTATUS (NTAPI*)(IN PWCHAR PathToFile OPTIONAL, IN ULONG Flags OPTIONAL, IN PUNICODE_STRING ModuleFileName, OUT PHANDLE ModuleHandle);
	using fnRtlInitUnicodeString = VOID (*)(PUNICODE_STRING DesinationString, PCWSTR SourceString);

	do {
		BobModule *ntdll = BOB_module_open(self->process, XORSTR("ntdll.dll"), SEARCH_DEFAULT);
		void *_LdrLoadDll = BOB_module_export(self->process, ntdll, XORSTR("LdrLoadDll"));
		void *_RtlInitUnicodeString = BOB_module_export(self->process, ntdll, XORSTR("RtlInitUnicodeString"));

		BOB_remote_begin_call64(self->worker);

		void *_RemotePath = BOB_remote_push(self->worker, NULL, sizeof(UNICODE_STRING));
		BOB_remote_push_wstr(self->worker, path);
		BOB_remote_call(self->worker, REMOTE_WIN64, _RtlInitUnicodeString);

		BOB_remote_push_ptr(self->worker, NULL);									// PathToFile (optional)
		BOB_remote_push_int(self->worker, 0);										// Flags
		BOB_remote_push_ptr(self->worker, _RemotePath);								// PathToFile
		void *_RemoteHandle = BOB_remote_push(self->worker, NULL, sizeof(HANDLE));  // ModuleHandle
		BOB_remote_call(self->worker, REMOTE_WIN64, _LdrLoadDll);
		BOB_remote_save(self->worker, 0);
		BOB_remote_notify(self->worker);

		BOB_remote_end_call64(self->worker);

		if (NT_SUCCESS(BOB_remote_exec(self->worker, NULL))) {
			HANDLE handle;
			if (BOB_process_read(self->process, _RemoteHandle, &handle, sizeof(HANDLE))) {
				return handle != NULL;
			}
		}
	} while (false);

	return false;
}

template<typename T = uintptr_t> BOB_STATIC BobModule *bob_mmap_dependency(ManualMap<T> *self, const char *name) {
	BobModule *module = BOB_module_open(self->process, static_cast<const char *>(name), SEARCH_DEFAULT);
	
	if (!module) {
		WCHAR wname[MAX_PATH] = {0};
		WCHAR wpath[MAX_PATH] = {0};
		MultiByteToWideChar(CP_UTF8, 0, name, -1, wname, ARRAYSIZE(wname));
		if (SearchPathW(NULL, wname, NULL, MAX_PATH, wpath, NULL)) {
			if (bob_mmap_dependency_ex(self, wpath)) {
				module = BOB_module_open(self->process, static_cast<const char *>(name), SEARCH_DEFAULT);
			}
		}
	}
	
	return module;
}

template<typename T1 = uintptr_t, typename T2> BOB_INLINE bool bob_mmap_thunk_is_ordinal(ManualMap<T1> *self, const T2 *thunk) {
	if (self->is64()) {
		return thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG64 != 0;
	}
	if (self->is32()) {
		return thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG32 != 0;
	}
	return false;
}

template<typename T = uintptr_t> BOB_STATIC bool bob_mmap_import(ManualMap<T> *self) {
	const IMAGE_IMPORT_DESCRIPTOR *descriptor;
	// Not the greatest way to do this, we load ALL the modules first and then we resolve imports!
	if ((descriptor = static_cast<const IMAGE_IMPORT_DESCRIPTOR *>(bob_mmap_directory(self, self->source, IMAGE_DIRECTORY_ENTRY_IMPORT)))) {
		for (; descriptor->Name; descriptor++) {
			const char *dll = static_cast<const char *>(bob_mmap_resolve_rva(self, descriptor->Name, self->source, ADDRESS_VA));
			BobModule *module = bob_mmap_dependency(self, dll);
		}
	}
	if ((descriptor = static_cast<const IMAGE_IMPORT_DESCRIPTOR *>(bob_mmap_directory(self, self->source, IMAGE_DIRECTORY_ENTRY_IMPORT)))) {
		for (; descriptor->Name; descriptor++) {
			const char *dll = static_cast<const char *>(bob_mmap_resolve_rva(self, descriptor->Name, self->source, ADDRESS_VA));
			BobModule *module = BOB_module_open(self->process, dll, SEARCH_DEFAULT);
			if (!module) {
				BOB_DEBUG_PRINT(stderr, XORSTR("[Error] Missing dependency module %s!\n"), dll);
				continue;
			}

			// @todo Better type convertion this is absolute horsehit
			if (descriptor->OriginalFirstThunk) {
				self->thunk = static_cast<decltype(self->thunk)>(bob_mmap_resolve_rva(self, descriptor->OriginalFirstThunk, self->source, ADDRESS_VA));
				self->func = static_cast<decltype(self->thunk)>(bob_mmap_resolve_rva(self, descriptor->FirstThunk, self->source, ADDRESS_VA));
			}
			else {
				self->thunk = static_cast<decltype(self->thunk)>(bob_mmap_resolve_rva(self, descriptor->FirstThunk, self->source, ADDRESS_VA));
				self->func = static_cast<decltype(self->func)>(bob_mmap_resolve_rva(self, descriptor->FirstThunk, self->source, ADDRESS_VA));
			}

			for (; self->thunk->u1.AddressOfData; self->thunk++, self->func++) {
				FARPROC address = NULL;

				if (bob_mmap_thunk_is_ordinal(self, self->thunk)) {
					WORD ordinal = self->thunk->u1.Ordinal & 0xFFFF;

					if (!(address = (FARPROC)BOB_module_export(self->process, module, reinterpret_cast<const char *>(ordinal)))) {
						BOB_DEBUG_PRINT(stderr, XORSTR("[Error] Import dependency %hd from image %s not found!\n"), ordinal, dll);
						return false;
					}
					BOB_DEBUG_PRINT(stdout, XORSTR("[Info] Import 0x%p | ID | %s:%hd\n"), address, dll, ordinal);
				}
				else {
					const IMAGE_IMPORT_BY_NAME *named = static_cast<const IMAGE_IMPORT_BY_NAME *>(bob_mmap_resolve_rva(self, self->thunk->u1.AddressOfData, self->source, ADDRESS_VA));

					if (!(address = (FARPROC)BOB_module_export(self->process, module, reinterpret_cast<const char *>(named->Name)))) {
						BOB_DEBUG_PRINT(stderr, XORSTR("[Error] Import dependency %s from image %s not found!\n"), named->Name, dll);
						return false;
					}
					BOB_DEBUG_PRINT(stderr, XORSTR("[Info] Import 0x%p | FN | %s:%s\n"), address, dll, named->Name);
				}

				self->func->u1.Function = reinterpret_cast<uintptr_t>(address);
			}
		}
	}
	return true;
}

template<typename T = uintptr_t> BOB_STATIC bool bob_mmap_import_delayed(ManualMap<T> *self) {
	const IMAGE_DELAYLOAD_DESCRIPTOR *descriptor;
	// Not the greatest way to do this, we load ALL the modules first and then we resolve imports!
	if ((descriptor = static_cast<const IMAGE_DELAYLOAD_DESCRIPTOR *>(bob_mmap_directory(self, self->source, IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT)))) {
		for (; descriptor->DllNameRVA; descriptor++) {
			const char *dll = static_cast<const char *>(bob_mmap_resolve_rva(self, descriptor->DllNameRVA, self->source, ADDRESS_VA));
			BobModule *module = bob_mmap_dependency(self, dll);
		}
	}
	if ((descriptor = static_cast<const IMAGE_DELAYLOAD_DESCRIPTOR *>(bob_mmap_directory(self, self->source, IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT)))) {
		for (; descriptor->DllNameRVA; descriptor++) {
			const char *dll = static_cast<const char *>(bob_mmap_resolve_rva(self, descriptor->DllNameRVA, self->source, ADDRESS_VA));
			BobModule *module = bob_mmap_dependency(self, dll);
			if (!module) {
				BOB_DEBUG_PRINT(stderr, XORSTR("[Error] Missing dependency module %s!\n"), dll);
				continue;
			}

			self->thunk = static_cast<decltype(self->thunk)>(bob_mmap_resolve_rva(self, descriptor->ImportNameTableRVA, self->source, ADDRESS_RVA));
			self->func = static_cast<decltype(self->func)>(bob_mmap_resolve_rva(self, descriptor->ImportAddressTableRVA, self->source, ADDRESS_RVA));

			for (; self->thunk->u1.AddressOfData; self->thunk++, self->func++) {
				FARPROC address = NULL;

				if (bob_mmap_thunk_is_ordinal(self, self->thunk)) {
					WORD ordinal = self->thunk->u1.Ordinal & 0xFFFF;

					if (!(address = (FARPROC)BOB_module_export(self->process, module, reinterpret_cast<const char *>(ordinal)))) {
						BOB_DEBUG_PRINT(stderr, XORSTR("[Error] Import dependency %hd from image %s not found!\n"), ordinal, dll);
						return false;
					}
					BOB_DEBUG_PRINT(stderr, XORSTR("[Info] DELAYED | Import 0x%p | ID | %s:%hd\n"), address, dll, ordinal);
				}
				else {
					const IMAGE_IMPORT_BY_NAME *named = static_cast<const IMAGE_IMPORT_BY_NAME *>(bob_mmap_resolve_rva(self, self->thunk->u1.AddressOfData, self->source, ADDRESS_VA));

					if (!(address = (FARPROC)BOB_module_export(self->process, module, reinterpret_cast<const char *>(named->Name)))) {
						BOB_DEBUG_PRINT(stderr, XORSTR("[Error] Import dependency %s from image %s not found!\n"), named->Name, dll);
						return false;
					}
					BOB_DEBUG_PRINT(stderr, XORSTR("[Info] DELAYED | Import 0x%p | FN | %s:%s\n"), address, dll, named->Name);
				}

				self->func->u1.Function = reinterpret_cast<uintptr_t>(address);
			}
		}
	}
	return true;
}

#ifndef IMR_RELTYPE
#	define IMR_RELTYPE(x) ((x >> 12) & 0xF)
#endif

#ifndef IMR_RELOFFSET
#	define IMR_RELOFFSET(x) (x & 0xFFF)
#endif

template<typename T = uintptr_t> BOB_INLINE bool bob_mmap_relocation(ManualMap<T> *self, ptrdiff_t delta, WORD data, PBYTE base) {
	switch (IMR_RELTYPE(data)) {
		case IMAGE_REL_BASED_HIGH: {
			SHORT *raw = (SHORT *)(base + IMR_RELOFFSET(data));
			SHORT backup = *raw;

			*raw += (ULONG)HIWORD(delta);

			BOB_DEBUG_PRINT(stdout, XORSTR("[Info] IMAGE_REL_BASED_HIGH 0x%p RELOCATED TO 0x%p\n"), backup, *raw);
		} return true;
		case IMAGE_REL_BASED_LOW: {
			SHORT *raw = (SHORT *)(base + IMR_RELOFFSET(data));
			SHORT backup = *raw;

			*raw += (ULONG)LOWORD(delta);

			BOB_DEBUG_PRINT(stdout, XORSTR("[Info] IMAGE_REL_BASED_LOW 0x%p RELOCATED TO 0x%p\n"), backup, *raw);
		} return true;
		case IMAGE_REL_BASED_HIGHLOW: {
			SIZE_T *raw = (SIZE_T *)(base + IMR_RELOFFSET(data));
			SIZE_T backup = *raw;

			*raw += (SIZE_T)delta;

			BOB_DEBUG_PRINT(stdout, XORSTR("[Info] IMAGE_REL_BASED_HIGHLOW 0x%p RELOCATED TO 0x%p\n"), backup, *raw);
		} return true;
		case IMAGE_REL_BASED_DIR64: {
			DWORD_PTR UNALIGNED *raw = (DWORD_PTR UNALIGNED *)(base + IMR_RELOFFSET(data));
			DWORD_PTR UNALIGNED backup = *raw;

			*raw += delta;

			BOB_DEBUG_PRINT(stdout, XORSTR("[Info] IMAGE_REL_BASED_DIR64 0x%p RELOCATED TO 0x%p\n"), backup, *raw);
		} return true;
		case IMAGE_REL_BASED_ABSOLUTE: {
			// No relocation needed, this is an absolute address.
		} return true;
		case IMAGE_REL_BASED_HIGHADJ: {
			// This is a high adjustment, we need to adjust the next relocation.
		} return true;
	}
	return false;
}

template<typename T = uintptr_t> BOB_STATIC bool bob_mmap_relocations(ManualMap<T> *self) {
	if (self->nt->FileHeader.Characteristics & IMAGE_FILE_RELOCS_STRIPPED) {
		return true;
	}

	ptrdiff_t delta = reinterpret_cast<uintptr_t>(self->remote) - static_cast<uintptr_t>(self->nt->OptionalHeader.ImageBase);

	const IMAGE_BASE_RELOCATION *itr;
	DWORD size = bob_mmap_directory_size(self, self->source, IMAGE_DIRECTORY_ENTRY_BASERELOC);
	if ((itr = static_cast<const IMAGE_BASE_RELOCATION *>(bob_mmap_directory(self, self->source, IMAGE_DIRECTORY_ENTRY_BASERELOC)))) {
		PVOID end = POINTER_OFFSET(itr, size);

		while (itr < end) {
			PBYTE relocation = static_cast<PBYTE>(bob_mmap_resolve_rva(self, itr->VirtualAddress, self->source, ADDRESS_VA));
			DWORD nrelocations = (itr->SizeOfBlock - 8) / sizeof(WORD);
			PWORD data = static_cast<PWORD>(POINTER_OFFSET(itr, sizeof(IMAGE_BASE_RELOCATION)));

			for (DWORD i = 0; i < nrelocations; i++, data++) {
				if (!bob_mmap_relocation(self, delta, *data, relocation)) {
					return false;
				}
			}

			itr = static_cast<const IMAGE_BASE_RELOCATION *>(POINTER_OFFSET(itr, itr->SizeOfBlock));
		}
	}

	return true;
}

template<typename T = uintptr_t> BOB_STATIC bool bob_mmap_section(ManualMap<T> *self, const IMAGE_SECTION_HEADER *section, int protection) {
	if (!BOB_process_write(self->process, POINTER_OFFSET(self->remote, section->VirtualAddress), POINTER_OFFSET(self->source, section->PointerToRawData), section->SizeOfRawData)) {
		return false;
	}

	if (!BOB_process_protect(self->process, POINTER_OFFSET(self->remote, section->VirtualAddress), section->Misc.VirtualSize, protection)) {
		return false;
	}
	return true;
}

template<typename T = uintptr_t> BOB_STATIC bool bob_mmap_sections(ManualMap<T> *self) {
	// Write the headers into the remote memory.
	if (!BOB_process_write(self->process, self->remote, self->source, self->nt->OptionalHeader.SizeOfHeaders)) {
		return false;
	}
	for (const IMAGE_SECTION_HEADER *section = self->begin(); section < self->end(); section++) {
		if (STREQ(reinterpret_cast<const char *>(section->Name), XORSTR(".reloc"))) {
			continue;
		}
		if (section->Characteristics & (IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE)) {
			int protection = 0;
			if ((section->Characteristics & IMAGE_SCN_MEM_READ) != 0) {
				protection |= PROTECT_R;
			}
			if ((section->Characteristics & IMAGE_SCN_MEM_WRITE) != 0) {
				protection |= PROTECT_W;
			}
			if ((section->Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0) {
				protection |= PROTECT_E;
			}
			if (!bob_mmap_section(self, section, protection)) {
				return false;
			}
		}
	}
	return true;
}

template<typename T = uintptr_t> BOB_STATIC bool bob_mmap_exceptions(ManualMap<T> *self) {
	const IMAGE_RUNTIME_FUNCTION_ENTRY *exptable = static_cast<const IMAGE_RUNTIME_FUNCTION_ENTRY *>(bob_mmap_directory(self, self->source, IMAGE_DIRECTORY_ENTRY_EXCEPTION));
	if (exptable) {
		void *address = POINTER_OFFSET(exptable, reinterpret_cast<uintptr_t>(self->remote) - reinterpret_cast<uintptr_t>(self->source));

		BobModule *ntdll = BOB_module_open(self->process, XORSTR("ntdll.dll"), SEARCH_DEFAULT);
		decltype(&RtlAddFunctionTable) _RtlAddFunctionTable = static_cast<decltype(&RtlAddFunctionTable)>(BOB_module_export(self->process, ntdll, XORSTR("RtlAddFunctionTable")));


		BOB_remote_begin_call64(self->worker);

		BOB_remote_push_ptr(self->worker, address);
		size_t size = bob_mmap_directory_size(self, self->source, IMAGE_DIRECTORY_ENTRY_EXCEPTION);
		BOB_remote_push_int(self->worker, size / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY));
		BOB_remote_push_ptr(self->worker, self->remote);
		BOB_remote_call(self->worker, REMOTE_WIN64, _RtlAddFunctionTable);
		BOB_remote_save(self->worker, 0);
		BOB_remote_notify(self->worker);

		BOB_remote_end_call64(self->worker);

		if (!BOB_remote_exec(self->worker, NULL)) {
			return false;
		}
	}
	return true;
}

template<typename T = uintptr_t> BOB_STATIC bool bob_mmap_entry(ManualMap<T> *self, FARPROC entry) {
	if (self->is64()) {
		BobModule *kernel32 = BOB_module_open(self->process, XORSTR("kernel32.dll"), SEARCH_DEFAULT);
		decltype(&ActivateActCtx) _ActivateActCtx = static_cast<decltype(&ActivateActCtx)>(BOB_module_export(self->process, kernel32, XORSTR("ActivateActCtx")));
		decltype(&DeactivateActCtx) _DeactivateActCtx = static_cast<decltype(&DeactivateActCtx)>(BOB_module_export(self->process, kernel32, XORSTR("DeactivateActCtx")));

		BOB_remote_begin_call64(self->worker);

		BOB_remote_push_ptr(self->worker, self->actctx);
		void *RemoteCookie = BOB_remote_push(self->worker, NULL, sizeof(ULONG_PTR));
		BOB_remote_call(self->worker, REMOTE_WIN64, _ActivateActCtx);
		BOB_remote_save(self->worker, 1);

		BOB_remote_push_ptr(self->worker, self->remote);
		BOB_remote_push_int(self->worker, DLL_PROCESS_ATTACH);
		BOB_remote_push_int(self->worker, 0);
		BOB_remote_call(self->worker, REMOTE_STDCALL, reinterpret_cast<void *>(entry));
		BOB_remote_save(self->worker, 0);

		BOB_remote_push_int(self->worker, 0);
		BOB_remote_push_ref8(self->worker, RemoteCookie);
		BOB_remote_call(self->worker, REMOTE_WIN64, _DeactivateActCtx);
		BOB_remote_save(self->worker, 2);

		BOB_remote_notify(self->worker);
		BOB_remote_end_call64(self->worker);

		if (!BOB_remote_exec(self->worker, NULL)) {
			// Do nothing! DllMain returned FALSE!
		}

		BOB_DEBUG_PRINT(stderr, XORSTR("[Warning] ActivateActCtx RETURN 0x%p\n"), (void *)BOB_remote_saved(self->worker, 1));
		BOB_DEBUG_PRINT(stderr, XORSTR("[Warning] DllMain RETURN 0x%p\n"), (void *)BOB_remote_saved(self->worker, 0));
		BOB_DEBUG_PRINT(stderr, XORSTR("[Warning] DeactivateActCtx RETURN 0x%p\n"), (void *)BOB_remote_saved(self->worker, 2));
		return true;
	}

	BOB_remote_push_ptr(self->worker, self->remote);
	BOB_remote_push_int(self->worker, DLL_PROCESS_ATTACH);
	BOB_remote_push_int(self->worker, 0);
	BOB_remote_call(self->worker, REMOTE_STDCALL, reinterpret_cast<void *>(entry));
	BOB_remote_save(self->worker, 0);
	BOB_remote_notify(self->worker);

	if (!BOB_remote_exec(self->worker, NULL)) {
		// Do nothing! DllMain returned FALSE!
	}

	return true;
}

template<typename T = uintptr_t> BOB_STATIC bool bob_mmap_tls(ManualMap<T> *self) {
	self->tls = static_cast<decltype(self->tls)>(bob_mmap_directory(self, self->source, IMAGE_DIRECTORY_ENTRY_TLS));
	if (self->tls) {
		if (!self->tls->AddressOfCallBacks) {
			return true;
		}

		PIMAGE_TLS_CALLBACK callbacks[0xFF];
		if (!BOB_process_read(self->process, (const void *)self->tls->AddressOfCallBacks, callbacks, sizeof(callbacks))) {
			return false;
		}

		bool status = true;
		for (int i = 0; callbacks[i]; i++) {
			if (!bob_mmap_entry(self, (FARPROC)callbacks[i])) {
				status &= false;
			}
		}
		return status;
	}
	return true;
}

template<typename T = uintptr_t> BOB_STATIC bool bob_mmap_cookie(ManualMap<T> *self) {
	return true;
}

/**
 * Nothing can be assumed to have been completed upon reaching here other than the structure itself initialized, 
 * The remote should point to a valid address in the remote process and source containing the image data.
 * 
 * \note The worker has been created and is ready to be used, but nothing has been done yet.
 */
template<typename T = uintptr_t> BOB_STATIC BobModule *bob_mmap_impl(ManualMap<T> *self) {
	if (self->is64()) {
		/** Create Remote Procedure Call environment. No need for this in 32 bit */
		if (!bob_mmap_actx(self)) {
			return NULL;
		}
	}

	if (bob_mmap_directory(self, self->remote, IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR)) {
		BOB_DEBUG_PRINT(stderr, XORSTR("[Error] This method is not supported for managed executables!"));
		return NULL;
	}

	if (!bob_mmap_import(self)) {
		return NULL;
	}

	if (!bob_mmap_import_delayed(self)) {
		return NULL;
	}

	if (!bob_mmap_relocations(self)) {
		return NULL;
	}

	if (!bob_mmap_sections(self)) {
		return NULL;
	}

	if (self->is64()) {
		if (!bob_mmap_exceptions(self)) {
			return NULL;
		}
	}

	if (!bob_mmap_tls(self)) {
		return NULL;
	}

	if (!bob_mmap_cookie(self)) {
		return NULL;
	}

	FARPROC entry = (FARPROC)POINTER_OFFSET(self->remote, self->nt->OptionalHeader.AddressOfEntryPoint);
	if (!bob_mmap_entry(self, entry)) {
		return NULL;
	}

	return reinterpret_cast<BobModule *>((uintptr_t)self->remote);
}

template<typename T = uintptr_t> BOB_STATIC void bob_mmap_exit(ManualMap<T> *self, bool failed = false) {
	BOB_remote_close(self->worker);

	if (failed) {
		BOB_process_free(self->process, self->remote);
	}
	BOB_FREE(self->source);
}

/** \} */

/* -------------------------------------------------------------------- */
/** \name Impl
* \{ */

struct BobModule *BOB_mmap_image(struct BobProc *process, const char *path, const void *image, size_t length, int flag) {
	IMAGE_DOS_HEADER *dos = static_cast<IMAGE_DOS_HEADER *>(const_cast<void *>(image));
	if (!dos || dos->e_magic != IMAGE_DOS_SIGNATURE) {
		BOB_DEBUG_PRINT(stderr, XORSTR("[Error] Invalid image signature!"));
		return NULL;
	}

	BobModule *address = NULL;

	do {
		IMAGE_NT_HEADERS *nt = static_cast<IMAGE_NT_HEADERS *>(POINTER_OFFSET(dos, dos->e_lfanew));
		if (nt->Signature != IMAGE_NT_SIGNATURE) {
			BOB_DEBUG_PRINT(stderr, XORSTR("[Error] Invalid NT signature!"));
			return NULL;
		}

		IMAGE_NT_HEADERS32 *nt32 = static_cast<IMAGE_NT_HEADERS32 *>(POINTER_OFFSET(dos, dos->e_lfanew));
		if (nt32->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
			ManualMap<uint32_t> self;
			if (bob_mmap_init(&self, process, image, length)) {
				address = bob_mmap_impl(&self);
			}
			bob_mmap_exit(&self, address == NULL);
			break;
		}

		IMAGE_NT_HEADERS64 *nt64 = static_cast<IMAGE_NT_HEADERS64 *>(POINTER_OFFSET(dos, dos->e_lfanew));
		if (nt64->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
			ManualMap<uint64_t> self;
			if (bob_mmap_init(&self, process, image, length)) {
				address = bob_mmap_impl(&self);
			}
			bob_mmap_exit(&self, address == NULL);
			break;
		}

		ManualMap<uintptr_t> self;
		if (bob_mmap_init(&self, process, image, length)) {
			address = bob_mmap_impl(&self);
		}
		bob_mmap_exit(&self, address == NULL);
	} while (false);

	BOB_DEBUG_PRINT(stdout, XORSTR("[Info] 0x%p!"), address);
	return address;
}

/** \} */

/* -------------------------------------------------------------------- */
/** \name Queries
 * \{ */

bool BOB_mmap_image_valid(const void *data, size_t length) {
	IMAGE_DOS_HEADER *dos = static_cast<IMAGE_DOS_HEADER *>(const_cast<void *>(data));
	if (!dos || dos->e_magic != IMAGE_DOS_SIGNATURE) {
#if BOB_DEBUG_MESSAGES
		fprintf(stderr, XORSTR("[ERR] Invalid image signature!"));
#endif
		return false;
	}

	do {
		IMAGE_NT_HEADERS *nt = static_cast<IMAGE_NT_HEADERS *>(POINTER_OFFSET(dos, dos->e_lfanew));
		if (nt->Signature != IMAGE_NT_SIGNATURE) {
			break;
		}

		IMAGE_NT_HEADERS32 *nt32 = static_cast<IMAGE_NT_HEADERS32 *>(POINTER_OFFSET(dos, dos->e_lfanew));
		if (nt32->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
			return true;
		}

		IMAGE_NT_HEADERS64 *nt64 = static_cast<IMAGE_NT_HEADERS64 *>(POINTER_OFFSET(dos, dos->e_lfanew));
		if (nt64->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
			return true;
		}

		if (nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR_MAGIC) {
			return true;
		}
	} while (false);

	return false;
}

/** \} */
