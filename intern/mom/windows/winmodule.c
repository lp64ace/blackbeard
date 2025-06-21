#include "MEM_guardedalloc.h"

#include "intern/mom_internal.h"
#include "mom.h"
#include "winmom.h" // Keep last!

#define DOS(handle) ((IMAGE_DOS_HEADER *)(handle->image))
#define NT32(handle) ((IMAGE_NT_HEADERS32 *)POINTER_OFFSET(handle->image, DOS(handle)->e_lfanew))
#define NT64(handle) ((IMAGE_NT_HEADERS64 *)POINTER_OFFSET(handle->image, DOS(handle)->e_lfanew))

/* -------------------------------------------------------------------- */
/** \name DLL Hell
 * { */

static bool winmom_module_schema_match(const wchar_t *wlogical, const char *search) {
	WCHAR wsearch[MAX_PATH];
	INT length = MultiByteToWideChar(CP_ACP, 0, search, -1, wsearch, ARRAYSIZE(wsearch));

	for (INT index = 0; wlogical[index]; index++) {
		if (towupper(wsearch[index]) != towupper(wlogical[index])) {
			return false;
		}
	}

	return true;
}

// Version 10

typedef struct _API_SET_VALUE_ENTRY_10 {
	ULONG Flags;
	ULONG NameOffset;
	ULONG NameLength;
	ULONG ValueOffset;
	ULONG ValueLength;
} API_SET_VALUE_ENTRY_10, *PAPI_SET_VALUE_ENTRY_10;

typedef struct _API_SET_VALUE_ARRAY_10 {
	ULONG Flags;
	ULONG NameOffset;
	ULONG Unk;
	ULONG NameLength;
	ULONG DataOffset;
	ULONG Count;
} API_SET_VALUE_ARRAY_10, *PAPI_SET_VALUE_ARRAY_10;

static inline PAPI_SET_VALUE_ENTRY_10 API_SET_VALUE_ARRAY_10_entry(PAPI_SET_VALUE_ARRAY_10 self, void *map, DWORD i) {
	return POINTER_OFFSET(map, self->DataOffset + i * sizeof(API_SET_VALUE_ENTRY_10));
}

typedef struct _API_SET_NAMESPACE_ENTRY_10 {
	ULONG Limit;
	ULONG Size;
} API_SET_NAMESPACE_ENTRY_10, *PAPI_SET_NAMESPACE_ENTRY_10;

typedef struct _API_SET_NAMESPACE_ARRAY_10 {
	ULONG Version;
	ULONG Size;
	ULONG Flags;
	ULONG Count;
	ULONG Start;
	ULONG End;
	ULONG Unk[2];
} API_SET_NAMESPACE_ARRAY_10, *PAPI_SET_NAMESPACE_ARRAY_10;

static inline PAPI_SET_NAMESPACE_ENTRY_10 API_SET_NAMESPACE_ARRAY_10_key(PAPI_SET_NAMESPACE_ARRAY_10 self, DWORD i) {
	return POINTER_OFFSET(self, self->End + i * sizeof(API_SET_NAMESPACE_ENTRY_10));
}

static inline PAPI_SET_VALUE_ARRAY_10 API_SET_NAMESPACE_ARRAY_10_value(PAPI_SET_NAMESPACE_ARRAY_10 self, PAPI_SET_NAMESPACE_ENTRY_10 key) {
	return POINTER_OFFSET(self, self->Start + sizeof(API_SET_VALUE_ARRAY_10) * key->Size);
}

DWORD API_SET_NAMESPACE_ARRAY_version(void *self) {
	return 10; // TODO Fix Me
}

/** \} */

/* -------------------------------------------------------------------- */
/** \name Module Platform Dependent
 * { */

/** Relative address is the address within the mapped image from disk. */
static void *winmom_module_resolve_relative_address(const ModuleHandle *handle, uintptr_t relative_address) {
	if ((void *)handle->disk == NULL || (void *)relative_address == NULL) {
		return NULL;
	}

	switch (MOM_module_architecture(handle)) {
		case kMomArchitectureAmd32: {
			const IMAGE_NT_HEADERS32 *nt = NT32(handle);

			for (IMAGE_SECTION_HEADER *header = IMAGE_FIRST_SECTION(nt); header != IMAGE_FIRST_SECTION(nt) + nt->FileHeader.NumberOfSections; header++) {
				if (header->VirtualAddress <= relative_address && relative_address < header->VirtualAddress + header->Misc.VirtualSize) {
					return POINTER_OFFSET((void *)handle->disk, relative_address - header->VirtualAddress + header->PointerToRawData);
				}
			}
		} break;
		case kMomArchitectureAmd64: {
			const IMAGE_NT_HEADERS64 *nt = NT64(handle);

			for (IMAGE_SECTION_HEADER *header = IMAGE_FIRST_SECTION(nt); header != IMAGE_FIRST_SECTION(nt) + nt->FileHeader.NumberOfSections; header++) {
				if (header->VirtualAddress <= relative_address && relative_address < header->VirtualAddress + header->Misc.VirtualSize) {
					return POINTER_OFFSET((void *)handle->disk, relative_address - header->VirtualAddress + header->PointerToRawData);
				}
			}
		} break;
	}

	return NULL;
}

/** Relative address is the address within the mapped image to memory. */
static void *winmom_module_resolve_virtual_address(const ModuleHandle *handle, uintptr_t virtual_address) {
	if ((void *)handle->real == NULL || (void *)virtual_address == NULL) {
		return NULL;
	}

	switch (MOM_module_architecture(handle)) {
		case kMomArchitectureAmd32: {
			const IMAGE_NT_HEADERS32 *nt = NT32(handle);

			// for (IMAGE_SECTION_HEADER *header = IMAGE_FIRST_SECTION(nt); header != IMAGE_FIRST_SECTION(nt) + nt->FileHeader.NumberOfSections; header++) {
			// 	if (header->VirtualAddress <= virtual_address && virtual_address < header->VirtualAddress + header->Misc.VirtualSize) {
			// 		return POINTER_OFFSET((void *)handle->real, virtual_address - nt->OptionalHeader.ImageBase + header->VirtualAddress);
			// 	}
			// }

			return POINTER_OFFSET((void *)handle->real, virtual_address);
		} break;
		case kMomArchitectureAmd64: {
			const IMAGE_NT_HEADERS64 *nt = NT64(handle);

			// for (IMAGE_SECTION_HEADER *header = IMAGE_FIRST_SECTION(nt); header != IMAGE_FIRST_SECTION(nt) + nt->FileHeader.NumberOfSections; header++) {
			// 	if (header->VirtualAddress <= virtual_address && virtual_address < header->VirtualAddress + header->Misc.VirtualSize) {
			// 		return POINTER_OFFSET((void *)handle->real, virtual_address - nt->OptionalHeader.ImageBase + header->VirtualAddress);
			// 	}
			// }

			return POINTER_OFFSET((void *)handle->real, virtual_address);
		} break;
	}

	return NULL;
}

HMODULE winmom_module_handle(const ModuleHandle *handle) {
	return (HMODULE)handle->real;
}

/** \} */

/* -------------------------------------------------------------------- */
/** \name Module Internal
 * { */

/* This cannot assume any data initialization within the #ModuleHandle other than the image itself! */
static bool winmom_module_header_is_valid(const ModuleHandle *handle) {
	if (((const IMAGE_DOS_HEADER *)handle->image)->e_magic != IMAGE_DOS_SIGNATURE) {
		return false;
	}
	const IMAGE_DOS_HEADER *dos = (const IMAGE_DOS_HEADER *)handle->image;
	if (((const IMAGE_NT_HEADERS32 *)POINTER_OFFSET(handle->image, dos->e_lfanew))->Signature == IMAGE_NT_SIGNATURE) {
		if (((const IMAGE_NT_HEADERS32 *)POINTER_OFFSET(handle->image, dos->e_lfanew))->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
			return true;
		}
	}
	if (((const IMAGE_NT_HEADERS64 *)POINTER_OFFSET(handle->image, dos->e_lfanew))->Signature == IMAGE_NT_SIGNATURE) {
		if (((const IMAGE_NT_HEADERS64 *)POINTER_OFFSET(handle->image, dos->e_lfanew))->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
			return true;
		}
	}
	return false;
}

/*
 * Image section header is consistent accross architectures!
 */
static IMAGE_SECTION_HEADER *winmom_module_native_section_begin(const ModuleHandle *handle) {
	switch (MOM_module_architecture(handle)) {
		case kMomArchitectureAmd32: {
			return IMAGE_FIRST_SECTION(NT32(handle));
		} break;
		case kMomArchitectureAmd64: {
			return IMAGE_FIRST_SECTION(NT64(handle));
		} break;
	}
	return NULL;
}

static IMAGE_SECTION_HEADER *winmom_module_native_section_end(const ModuleHandle *handle) {
	switch (MOM_module_architecture(handle)) {
		case kMomArchitectureAmd32: {
			return IMAGE_FIRST_SECTION(NT32(handle)) + NT32(handle)->FileHeader.NumberOfSections;
		} break;
		case kMomArchitectureAmd64: {
			return IMAGE_FIRST_SECTION(NT64(handle)) + NT64(handle)->FileHeader.NumberOfSections;
		} break;
	}
	return NULL;
}

static size_t winmom_module_native_directory_size(const ModuleHandle *handle, int directory) {
	switch (MOM_module_architecture(handle)) {
		case kMomArchitectureAmd32: {
			return NT32(handle)->OptionalHeader.DataDirectory[directory].Size;
		} break;
		case kMomArchitectureAmd64: {
			return NT64(handle)->OptionalHeader.DataDirectory[directory].Size;
		} break;
	}
	return 0;
}

static DWORD winmom_module_native_directory_address(const ModuleHandle *handle, int directory) {
	switch (MOM_module_architecture(handle)) {
		case kMomArchitectureAmd32: {
			const IMAGE_NT_HEADERS32 *nt = NT32(handle);

			if (!nt->OptionalHeader.DataDirectory[directory].Size) {
				return 0;
			}

			return nt->OptionalHeader.DataDirectory[directory].VirtualAddress;
		} break;
		case kMomArchitectureAmd64: {
			const IMAGE_NT_HEADERS64 *nt = NT64(handle);

			if (!nt->OptionalHeader.DataDirectory[directory].Size) {
				return 0;
			}

			return nt->OptionalHeader.DataDirectory[directory].VirtualAddress;
		} break;
	}
	return 0;
}

static void *winmom_module_native_relative_directory(const ModuleHandle *handle, int directory) {
	return winmom_module_resolve_relative_address(handle, winmom_module_native_directory_address(handle, directory));
}

static void *winmom_module_native_virtual_directory(const ModuleHandle *handle, int directory) {
	return winmom_module_resolve_virtual_address(handle, winmom_module_native_directory_address(handle, directory));
}

static void *winmom_module_native_directory(const ModuleHandle *handle, int directory) {
	void *buffer = NULL;
	void *itr;

	DWORD address = winmom_module_native_directory_address(handle, directory);
	if ((itr = winmom_module_native_relative_directory(handle, directory))) {
		buffer = MEM_callocN(winmom_module_native_directory_size(handle, directory), "module-directory");
		memcpy(buffer, itr, winmom_module_native_directory_size(handle, directory));
	}
	if ((itr = winmom_module_native_virtual_directory(handle, directory))) {
		buffer = MEM_callocN(winmom_module_native_directory_size(handle, directory), "module-directory");
		do {
			if (!handle->process) {
				memcpy(buffer, itr, winmom_module_native_directory_size(handle, directory));
				break;
			}
			if (!winmom_process_read(handle->process, itr, buffer, winmom_module_native_directory_size(handle, directory))) {
				memcpy(buffer, itr, winmom_module_native_directory_size(handle, directory));
				break;
			}
		} while (false);
	}

	return buffer;
}

/** \} */

/* -------------------------------------------------------------------- */
/** \name Module
 * { */

eMomArchitecture winmom_module_architecture(const ModuleHandle *handle) {
	const IMAGE_DOS_HEADER *dos = (const IMAGE_DOS_HEADER *)handle->image;
	if (((const IMAGE_NT_HEADERS32 *)POINTER_OFFSET(handle->image, dos->e_lfanew))->Signature == IMAGE_NT_SIGNATURE) {
		if (((const IMAGE_NT_HEADERS32 *)POINTER_OFFSET(handle->image, dos->e_lfanew))->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
			return kMomArchitectureAmd32;
		}
	}
	if (((const IMAGE_NT_HEADERS64 *)POINTER_OFFSET(handle->image, dos->e_lfanew))->Signature == IMAGE_NT_SIGNATURE) {
		if (((const IMAGE_NT_HEADERS64 *)POINTER_OFFSET(handle->image, dos->e_lfanew))->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
			return kMomArchitectureAmd64;
		}
	}
	return kMomArchitectureNone;
}

static ModuleHandle *winmom_module_open_by_file_from_disk(const char *fullpath) {
	ModuleHandle *handle = NULL;

	HANDLE fpin = CreateFile(fullpath, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, 0, 0);
	if (fpin == INVALID_HANDLE_VALUE) {
		return handle;
	}

	/**
	 * The new DLLs with the long names are anyway just stubs in which all exported 
	 * functions are implemented no more than needed for hard-coded failure. Moreover, 
	 * these failing implementations have not all received great care: see for instance 
	 * that CreateFileW in API-MS-Win-Core-File-L1-1-0.dll returns a hard-coded NULL 
	 * (0) instead of INVALID_HANDLE_VALUE (-1). 
	 * 
	 * https://www.geoffchappell.com/studies/windows/win32/apisetschema/index.htm
	 * 
	 * \note I have never actually seen this happen (didn't try to test it)!
	 */
	if (fpin == NULL) {
		return handle;
	}

	LARGE_INTEGER size;
	if (GetFileSizeEx(fpin, &size)) {
		void *image = MEM_mallocN((size_t)size.QuadPart, "image");

		size_t total = 0;
		while (total < size.QuadPart) {
			DWORD toread = (size.QuadPart - total < 0x1000) ? size.QuadPart - total : 0x1000;
			DWORD inread;
			if (!ReadFile(fpin, POINTER_OFFSET(image, total), toread, &inread, NULL)) {
				break;
			}

			total = total + inread;
		}

		handle = MOM_module_open_by_image(image, total);

		MEM_SAFE_FREE(image);
	}

	CloseHandle(fpin);

	return handle;
}

static ModuleHandle *winmom_module_open_by_file_from_name(const char *name) {
	ModuleHandle *handle = NULL;

	CHAR buffer[MAX_PATH];
	if (SearchPathA(NULL, name, NULL, MAX_PATH, buffer, NULL)) {
		if ((handle = winmom_module_open_by_file_from_disk(buffer))) {
			return handle;
		}
	}

	return handle;
}

/**
 * schemanames are absolutely nuts here are some name layouts;
 *  - [EXT-MS-WIN-][Schema-Name-Separated]-L[MajorVersion-MinorVersion](-RevisionVersion)(.dll)
 *  - [API-MS-WIN-][Schema-Name-Separated]-L[MajorVersion-MinorVersion](-RevisionVersion)(.dll)
 */
static ModuleHandle *winmom_module_open_by_file_from_schema(const char *schemaname) {
	ModuleHandle *handle = NULL, *last = NULL;
	ProcessHandle *self = MOM_process_self();

	PEB peb;
	if (winmom_process_peb(self, &peb)) {
		do {
			if (!peb.Reserved9[0]) {
				break;
			}

			switch (API_SET_NAMESPACE_ARRAY_version(peb.Reserved9[0])) {
				case 10: {
					PAPI_SET_NAMESPACE_ARRAY_10 map = (PAPI_SET_NAMESPACE_ARRAY_10)peb.Reserved9[0];

					for (DWORD i = 0; i < map->Count; i++) {
						WCHAR wlogical[MAX_PATH], wphysical[MAX_PATH];

						memset(wlogical, 0, sizeof(wlogical));
						PAPI_SET_NAMESPACE_ENTRY_10 key = API_SET_NAMESPACE_ARRAY_10_key(map, i);
						PAPI_SET_VALUE_ARRAY_10 value = API_SET_NAMESPACE_ARRAY_10_value(map, key);
						memcpy(wlogical, POINTER_OFFSET(map, value->NameOffset), value->NameLength);

						for (DWORD j = 0; j < value->Count; j++) {
							PAPI_SET_VALUE_ENTRY_10 host = API_SET_VALUE_ARRAY_10_entry(value, map, j);

							memset(wphysical, 0, sizeof(wphysical));
							memcpy(wphysical, POINTER_OFFSET(map, host->ValueOffset), host->ValueLength);

							if (winmom_module_schema_match(wlogical, schemaname)) {
								CHAR physical[MAX_PATH];
								WideCharToMultiByte(CP_ACP, 0, wphysical, -1, physical, ARRAYSIZE(physical), 0, NULL);

								ModuleHandle *new = NULL;
								if ((new = winmom_module_open_by_file_from_name(physical))) {
									if (last) {
										last->next = new;
									}
									new->prev = last;
									last = new;
								}

								handle = (handle) ? handle : new;
							}
						}
					}
				} break;
			}
		} while (false);
	}

	MOM_process_close(self);
	return handle;
}

ModuleHandle *winmom_module_open_by_file(const char *filename) {
	ModuleHandle *handle = NULL;

	if ((handle = winmom_module_open_by_file_from_schema(filename))) {
		return handle;
	}
	if ((handle = winmom_module_open_by_file_from_name(filename))) {
		return handle;
	}
	if ((handle = winmom_module_open_by_file_from_disk(filename))) {
		return handle;
	}

	return handle;
}

typedef void *(*fnMomCallbackLdr)(ProcessHandle *process, LDR_DATA_TABLE_ENTRY *entry, void *userdata);

static inline void *winmom_module_enum(ProcessHandle *process, fnMomCallbackLdr proc, void *userdata) {
	PEB peb;
	PEB_LDR_DATA ldr;
	if (!winmom_process_peb(process, &peb)) {
		return NULL;
	}
	/**
	 * PEB::Ldr already points to a pointer, even through it is not named pLdr!
	 *
	 * https://www.geoffchappell.com/studies/windows/km/ntoskrnl/inc/api/pebteb/peb/index.htm?tx=179
	 */
	if (!winmom_process_read(process, peb.Ldr, &ldr, sizeof(PEB_LDR_DATA))) {
		return NULL;
	}

	size_t total = 0;

	LIST_ENTRY *head = POINTER_OFFSET(peb.Ldr, FIELD_OFFSET(PEB_LDR_DATA, InMemoryOrderModuleList));
	for (LIST_ENTRY link = ldr.InMemoryOrderModuleList; link.Flink != head; winmom_process_read(process, link.Flink, &link, sizeof(link))) {
		LDR_DATA_TABLE_ENTRY local;

		LDR_DATA_TABLE_ENTRY *remote = CONTAINING_RECORD(link.Flink, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
		if (!(BOOL)winmom_process_read(process, remote, &local, sizeof(local))) {
			continue;
		}

		uint8_t raw[0xBAD];
		if (!(BOOL)winmom_process_read(process, local.FullDllName.Buffer, raw, local.FullDllName.MaximumLength)) {
			continue;
		}
		local.FullDllName.Buffer = (PWSTR)raw;

		void *ret = NULL;
		if ((ret = proc(process, &local, userdata)) != NULL) {
			return ret;
		}

		total++;
	}

	return NULL;
}

static inline void *winmom_module_loaded_match_name(ProcessHandle *process, LDR_DATA_TABLE_ENTRY *entry, void *name) {
	CHAR FullDllName[MAX_PATH * 4];
	int MaxLength = WideCharToMultiByte(CP_ACP, 0, entry->FullDllName.Buffer, entry->FullDllName.MaximumLength, FullDllName, ARRAYSIZE(FullDllName), 0, NULL);

	for (size_t offset = 0; offset < MaxLength && FullDllName[offset]; offset++) {
		if (FullDllName[offset] == L'\\' || FullDllName[offset] == L'/') {
			if (_stricmp(POINTER_OFFSET(FullDllName, offset + 1), name) == 0) {
				return MOM_module_open_by_address(process, entry->DllBase, (size_t)entry->Reserved3[1]);
			}
		}
	}

	return _stricmp(FullDllName, name) == 0 ? MOM_module_open_by_address(process, entry->DllBase, (size_t)entry->Reserved3[1]) : NULL;
}

ModuleHandle *winmom_module_open_by_name(ProcessHandle *process, const char *name) {
	ModuleHandle *handle = NULL;
	if ((handle = winmom_module_enum(process, winmom_module_loaded_match_name, (void *)name))) {
		return handle;
	}
	return NULL;
}

ModuleHandle *winmom_module_open_by_image(const void *image, size_t length) {
	ModuleHandle *handle = MEM_callocN(sizeof(ModuleHandle) + length, "module");
	
	handle->disk = (uintptr_t)handle->image;
	memcpy(handle->image, image, length);

	switch (MOM_module_architecture(handle)) {
		case kMomArchitectureAmd32: {
			IMAGE_NT_HEADERS32 *nt = NT32(handle);

			handle->base = nt->OptionalHeader.ImageBase;
		} break;
		case kMomArchitectureAmd64: {
			IMAGE_NT_HEADERS64 *nt = NT64(handle);

			handle->base = nt->OptionalHeader.ImageBase;
		} break;
	}

	return handle;
}

ModuleHandle *winmom_module_open_by_address(ProcessHandle *process, const void *address, size_t length) {
	ModuleHandle *handle = MEM_callocN(sizeof(ModuleHandle) + length, "module");

	handle->real = (uintptr_t)address;
	handle->process = process;
	if (process) {
		winmom_process_read(handle->process, address, handle->image, length);
	}
	else {
		memcpy(handle->image, address, length);
	}

	switch (MOM_module_architecture(handle)) {
		case kMomArchitectureAmd32: {
			IMAGE_NT_HEADERS32 *nt = NT32(handle);

			handle->base = nt->OptionalHeader.ImageBase;
		} break;
		case kMomArchitectureAmd64: {
			IMAGE_NT_HEADERS64 *nt = NT64(handle);

			handle->base = nt->OptionalHeader.ImageBase;
		} break;
	}

	return handle;
}

void winmom_module_close(ModuleHandle *handle) {
	ModuleHandle *prev = handle->prev, *next = handle->next;

	LIST_FOREACH_MUTABLE(ModuleSection *, section, handle->sections) {
		MEM_SAFE_FREE(section);
	}
	LIST_FOREACH_MUTABLE(ModuleExport *, export, handle->exports) {
		MEM_SAFE_FREE(export);
	}
	LIST_FOREACH_MUTABLE(ModuleImport *, import, handle->imports) {
		MEM_SAFE_FREE(import);
	}
	LIST_FOREACH_MUTABLE(ModuleImport *, import, handle->delayed_imports) {
		MEM_SAFE_FREE(import);
	}

	if (handle->next) {
		handle->next->prev = NULL;
	}
	if (handle->prev) {
		handle->prev->next = NULL;
	}

	MEM_SAFE_FREE(handle);

	if (prev) {
		winmom_module_close(prev);
	}
	if (next) {
		winmom_module_close(next);
	}
}

void *winmom_module_address(ModuleHandle *handle) {
	return (void *)handle->real;
}

size_t winmom_module_size(const ModuleHandle *handle) {
	uintptr_t lo = 0x7FFFFFFFFFFFFFFF;
	uintptr_t hi = 0x0000000000000000;
	for (IMAGE_SECTION_HEADER *section = winmom_module_native_section_begin(handle); section != winmom_module_native_section_end(handle); section++) {
		lo = (lo < section->VirtualAddress) ? lo : section->VirtualAddress;
		hi = (hi > section->VirtualAddress + section->Misc.VirtualSize) ? hi : section->VirtualAddress + section->Misc.VirtualSize;
	}
	return (hi - lo);
}

ModuleSection *winmom_module_section_begin(ModuleHandle *handle) {
	if (!handle->sections) {
		ModuleSection *new = MEM_callocN(sizeof(ModuleSection) + sizeof(IMAGE_SECTION_HEADER), "section"), *last = NULL;

		IMAGE_SECTION_HEADER buffer;
		IMAGE_SECTION_HEADER *header;

		for (IMAGE_SECTION_HEADER *itr = winmom_module_native_section_begin(handle); itr != winmom_module_native_section_end(handle); itr++) {
			header = itr;
			if (handle->process) {
				if (winmom_process_read(handle->process, itr, &buffer, sizeof(buffer))) {
					header = &buffer;
				}
			}
			new->prev = last;
			new->src = (uintptr_t)winmom_module_resolve_relative_address(handle, header->VirtualAddress);
			new->dst = (uintptr_t)winmom_module_resolve_virtual_address(handle, header->VirtualAddress);
			memcpy(new->header, header, sizeof(IMAGE_SECTION_HEADER));

			if (!handle->sections) {
				handle->sections = last = new;
			}
			last = new;
			last->next = new = MEM_callocN(sizeof(ModuleSection) + sizeof(IMAGE_SECTION_HEADER), "section");
		}

		if (last != NULL) {
			/*
			 * Unless the image is an invalid PE this should never happen!
			 */
			last->next = NULL;
		}

		MEM_SAFE_FREE(new);
	}

	return handle->sections;
}

const char *winmom_module_section_name(const ModuleHandle *handle, const ModuleSection *section) {
	if (!section) {
		return NULL;
	}

	const IMAGE_SECTION_HEADER *header = (const IMAGE_SECTION_HEADER *)section->header;
	return header->Name;
}

void *winmom_module_section_disk(const ModuleHandle *handle, ModuleSection *section) {
	if (!section->src) {
		const IMAGE_SECTION_HEADER *header = (const IMAGE_SECTION_HEADER *)section->header;
		section->src = (uintptr_t)winmom_module_resolve_relative_address(handle, header->VirtualAddress);
	}
	return (void *)section->src;
}

void *winmom_module_section_memory(const ModuleHandle *handle, ModuleSection *section) {
	if (!section->dst) {
		const IMAGE_SECTION_HEADER *header = (const IMAGE_SECTION_HEADER *)section->header;
		section->dst = (uintptr_t)winmom_module_resolve_virtual_address(handle, header->VirtualAddress);
	}
	return (void *)section->dst;
}

size_t winmom_module_section_size(const ModuleHandle *handle, const ModuleSection *section) {
	if (!section) {
		return 0;
	}

	const IMAGE_SECTION_HEADER *header = (const IMAGE_SECTION_HEADER *)section->header;
	return header->Misc.VirtualSize;
}

ModuleExport *winmom_module_export_begin(ModuleHandle *handle) {
	if (!handle->exports) {
		ModuleExport *new = MEM_callocN(sizeof(ModuleExport), "export"), *last = NULL;

		IMAGE_EXPORT_DIRECTORY *directory = winmom_module_native_directory(handle, IMAGE_DIRECTORY_ENTRY_EXPORT);
		DWORD address = winmom_module_native_directory_address(handle, IMAGE_DIRECTORY_ENTRY_EXPORT);

		if (directory) {
			DWORD *func = POINTER_OFFSET(directory, directory->AddressOfFunctions - address);
			DWORD *name = POINTER_OFFSET(directory, directory->AddressOfNames - address);
			WORD *ordi = POINTER_OFFSET(directory, directory->AddressOfNameOrdinals - address);

			for (DWORD index = 0; index < directory->NumberOfFunctions; index++) {
				bool named = false;

				new->prev = last;
				new->ordinal = index;

				if (address <= func[index] && func[index] <= address + winmom_module_native_directory_size(handle, IMAGE_DIRECTORY_ENTRY_EXPORT)) {
					char forward[MOM_MAX_LIBNAME_LEN + MOM_MAX_EXPNAME_LEN];
					memcpy(forward, POINTER_OFFSET(directory, func[index] - address), ARRAYSIZE(new->libname));
					if (sscanf(forward, "%[^.].%s", new->libname, new->fwdname) > 0) {
						snprintf(new->libname, MOM_MAX_LIBNAME_LEN, "%s.dll", new->libname);

						if (new->fwdname[0] == '#') {
							new->ordinal = atoi(new->fwdname + 1);
							new->fwdname[0] = '\0';
						}
						named |= true;
					}
				}
				else {
					new->src = (uintptr_t)winmom_module_resolve_relative_address(handle, func[index]);
					new->dst = (uintptr_t)winmom_module_resolve_virtual_address(handle, func[index]);
				}

				for (DWORD nindex = 0; nindex < directory->NumberOfNames; nindex++) {
					if (ordi[nindex] == index) {
						do {
							if (handle->process) {
								if (winmom_process_read(handle->process, winmom_module_resolve_virtual_address(handle, name[nindex]), new->expname, ARRAYSIZE(new->expname))) {
									break;
								}
							}
							memcpy(new->expname, winmom_module_resolve_relative_address(handle, name[nindex]), ARRAYSIZE(new->expname));
						} while (false);
					}
				}

				if (!handle->exports) {
					handle->exports = last = new;
				}
				last = new;
				last->next = new = MEM_callocN(sizeof(ModuleExport), "section");
			}
		}

		if (last != NULL) {
			// This will happen in the unlikely case that the module has no exports!
			last->next = NULL;
		}

		MEM_SAFE_FREE(directory);
		MEM_SAFE_FREE(new);
	}

	return handle->exports;
}

ModuleExport *winmom_module_export_find_by_name(ModuleHandle *handle, const char *name) {
	for (ModuleExport *export = MOM_module_export_begin(handle); export != MOM_module_export_end(handle); export = MOM_module_export_next(handle, export)) {
		if (strcmp(export->expname, name) == 0) {
			return export;
		}
	}
	return NULL;
}

ModuleExport *winmom_module_export_find_by_ordinal(ModuleHandle *handle, int ordinal) {
	for (ModuleExport *export = MOM_module_export_begin(handle); export != MOM_module_export_end(handle); export = MOM_module_export_next(handle, export)) {
		if (export->ordinal == ordinal) {
			return export;
		}
	}
	return NULL;
}

void *winmom_module_export_disk(const ModuleHandle *handle, const ModuleExport *export) {
	return (void *)export->src;
}

void *winmom_module_export_memory(const ModuleHandle *handle, const ModuleExport *export) {
	return (void *)export->dst;
}

static void winmom_module_import_make(ModuleHandle *handle, ModuleImport *import, void *vthunk, void *vfunk, const char *libname) {
	uintptr_t address = 0;

	switch (MOM_module_architecture(handle)) {
		case kMomArchitectureAmd32: {
			IMAGE_THUNK_DATA32 *thunk = vthunk;
			IMAGE_THUNK_DATA32 *funk = vfunk;

			if (IMAGE_SNAP_BY_ORDINAL32(thunk->u1.Ordinal)) {
				import->ordinal = IMAGE_ORDINAL32(thunk->u1.Ordinal);
			}
			else {
				address = thunk->u1.AddressOfData;
			}
		} break;
		case kMomArchitectureAmd64: {
			IMAGE_THUNK_DATA64 *thunk = vthunk;
			IMAGE_THUNK_DATA64 *funk = vfunk;

			if (IMAGE_SNAP_BY_ORDINAL64(thunk->u1.Ordinal)) {
				import->ordinal = IMAGE_ORDINAL64(thunk->u1.Ordinal);
			}
			else {
				address = thunk->u1.AddressOfData;
			}
		} break;
	}

	if (address) {
		IMAGE_IMPORT_BY_NAME *image = MEM_mallocN(sizeof(IMAGE_IMPORT_BY_NAME) + MOM_MAX_EXPNAME_LEN, "import-by-name");

		do {
			if (handle->process) {
				if (winmom_process_read(handle->process, winmom_module_resolve_virtual_address(handle, address), image, MOM_MAX_EXPNAME_LEN)) {
					continue;
				}
			}

			memcpy(image, winmom_module_resolve_relative_address(handle, address), MOM_MAX_EXPNAME_LEN);
		} while (false);

		memcpy(import->expname, image->Name, MOM_MAX_EXPNAME_LEN);

		MEM_SAFE_FREE(image);
	}

	memcpy(import->libname, libname, MOM_MAX_LIBNAME_LEN);
}

ModuleImport *winmom_module_import_begin(ModuleHandle *handle) {
	if (!handle->imports) {
		ModuleImport *new = MEM_callocN(sizeof(ModuleImport), "import"), *last = NULL;

		IMAGE_IMPORT_DESCRIPTOR *directory = winmom_module_native_directory(handle, IMAGE_DIRECTORY_ENTRY_IMPORT);
		DWORD address = winmom_module_native_directory_address(handle, IMAGE_DIRECTORY_ENTRY_IMPORT);

		for (IMAGE_IMPORT_DESCRIPTOR *desc = directory; desc->Name != 0; desc++) {
			char libname[MOM_MAX_LIBNAME_LEN];

			do {
				if (handle->process) {
					if (winmom_process_read(handle->process, winmom_module_resolve_virtual_address(handle, desc->Name), libname, ARRAYSIZE(libname))) {
						break;
					}
				}

				memcpy(libname, winmom_module_resolve_relative_address(handle, desc->Name), ARRAYSIZE(libname));
			} while (false);

			void *thunk = NULL;
			void *funk = NULL;

			if (!desc->OriginalFirstThunk) {
				// This is a copy of the data we don't actually change anything here!
				desc->OriginalFirstThunk = desc->FirstThunk;
			}

			do {
				if ((thunk = winmom_module_resolve_virtual_address(handle, desc->OriginalFirstThunk))) {
					funk = winmom_module_resolve_virtual_address(handle, desc->FirstThunk);
					break;
				}
				if ((thunk = winmom_module_resolve_relative_address(handle, desc->OriginalFirstThunk))) {
					funk = winmom_module_resolve_relative_address(handle, desc->FirstThunk);
					break;
				}
				// What?!
			} while (false);

			/*
			 * Gotta give a huge thumbs up to microsoft here!
			 * The compiler actually doesn't break my ballz for thunk that may be NULL.
			 *
			 * And logically the funk will be NON-NULL if and only if thunk is NON-NULL.
			 */
			if (!funk) {
				continue;
			}

			/*
			 * If this was CXX and we had constexpr this would be
			 * static_assert(sizeof(IMAGE_THUNK_DATA32) == MOM_module_architecture_pointer_size(kMomArchitectureAmd32), ...);
			 * static_assert(sizeof(IMAGE_THUNK_DATA64) == MOM_module_architecture_pointer_size(kMomArchitectureAmd64), ...);
			 */
			static_assert(sizeof(IMAGE_THUNK_DATA32) == sizeof(int32_t), "Bad thunk iteration");
			static_assert(sizeof(IMAGE_THUNK_DATA64) == sizeof(int64_t), "Bad thunk iteration");

			uint64_t zero = 0;

			/*
			 * You think this is fucked, and impossible to understand? You shouldn't open the source code!
			 *
			 * TL;DR Thunks are unions that contain ordinal or name offset and data address,
			 * when zero (memcmp(thunk, &zero, MOM_module_architecture_pointer_size(architecture)) == 0) stop!
			 */
			eMomArchitecture architecture = MOM_module_architecture(handle);
			for (uintptr_t expindex = 0; memcmp(thunk, &zero, MOM_module_architecture_pointer_size(architecture)); expindex++) {
				new->prev = last;
				winmom_module_import_make(handle, new, thunk, funk, libname);

				new->src = desc->OriginalFirstThunk + expindex * MOM_module_architecture_pointer_size(architecture); // VA
				new->dst = desc->FirstThunk + expindex * MOM_module_architecture_pointer_size(architecture); // VA

				if (!handle->imports) {
					handle->imports = last = new;
				}
				last = new;
				last->next = new = MEM_callocN(sizeof(ModuleImport), "import");

				thunk = POINTER_OFFSET(thunk, MOM_module_architecture_pointer_size(architecture));
				funk = POINTER_OFFSET(funk, MOM_module_architecture_pointer_size(architecture));
			}
		}

		if (last != NULL) {
			// This will happen in the unlikely case that the module has no imports!
			last->next = NULL;
		}

		MEM_SAFE_FREE(directory);
		MEM_SAFE_FREE(new);
	}

	return handle->imports;
}

void *winmom_module_import_from_disk(const ModuleHandle *handle, const ModuleImport *import) {
	return winmom_module_resolve_relative_address(handle, import->src);
}

void *winmom_module_import_to_disk(const ModuleHandle *handle, const ModuleImport *import) {
	return winmom_module_resolve_relative_address(handle, import->dst);
}

void *winmom_module_import_from_memory(const ModuleHandle *handle, const ModuleImport *import) {
	return winmom_module_resolve_virtual_address(handle, import->src);
}

void *winmom_module_import_to_memory(const ModuleHandle *handle, const ModuleImport *import) {
	return winmom_module_resolve_virtual_address(handle, import->dst);
}

ModuleImport *winmom_module_import_delayed_begin(ModuleHandle *handle) {
	if (!handle->delayed_imports) {
		ModuleImport *new = MEM_callocN(sizeof(ModuleImport), "import-delayed"), *last = NULL;

		IMAGE_DELAYLOAD_DESCRIPTOR *directory = winmom_module_native_directory(handle, IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT);
		DWORD address = winmom_module_native_directory_address(handle, IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT);

		for (IMAGE_DELAYLOAD_DESCRIPTOR *desc = directory; desc->DllNameRVA != 0; desc++) {
			char libname[MOM_MAX_LIBNAME_LEN];

			do {
				if (handle->process) {
					if (winmom_process_read(handle->process, winmom_module_resolve_virtual_address(handle, desc->DllNameRVA), libname, ARRAYSIZE(libname))) {
						break;
					}
				}

				memcpy(libname, winmom_module_resolve_relative_address(handle, desc->DllNameRVA), ARRAYSIZE(libname));
			} while (false);

			void *thunk = NULL;
			void *funk = NULL;

			do {
				if ((thunk = winmom_module_resolve_virtual_address(handle, desc->ImportNameTableRVA))) {
					funk = winmom_module_resolve_virtual_address(handle, desc->ImportAddressTableRVA);
					break;
				}
				if ((thunk = winmom_module_resolve_relative_address(handle, desc->ImportNameTableRVA))) {
					funk = winmom_module_resolve_relative_address(handle, desc->ImportAddressTableRVA);
					break;
				}
				// What?!
			} while (false);

			/*
			 * Gotta give a huge thumbs up to microsoft here!
			 * The compiler actually doesn't break my ballz for thunk that may be NULL.
			 *
			 * And logically the funk will be NON-NULL if and only if thunk is NON-NULL.
			 */
			if (!funk) {
				continue;
			}

			/*
			 * If this was CXX and we had constexpr this would be
			 * static_assert(sizeof(IMAGE_THUNK_DATA32) == MOM_module_architecture_pointer_size(kMomArchitectureAmd32), ...);
			 * static_assert(sizeof(IMAGE_THUNK_DATA64) == MOM_module_architecture_pointer_size(kMomArchitectureAmd64), ...);
			 */
			static_assert(sizeof(IMAGE_THUNK_DATA32) == sizeof(int32_t), "Bad thunk iteration");
			static_assert(sizeof(IMAGE_THUNK_DATA64) == sizeof(int64_t), "Bad thunk iteration");

			uint64_t zero = 0;

			/*
			 * You think this is fucked, and impossible to understand? You shouldn't open the source code!
			 *
			 * TL;DR Thunks are unions that contain ordinal or name offset and data address,
			 * when zero (memcmp(thunk, &zero, MOM_module_architecture_pointer_size(architecture)) == 0) stop!
			 */
			eMomArchitecture architecture = MOM_module_architecture(handle);
			for (uintptr_t expindex = 0; memcmp(thunk, &zero, MOM_module_architecture_pointer_size(architecture)); expindex++) {
				new->prev = last;
				winmom_module_import_make(handle, new, thunk, funk, libname);

				new->src = desc->ImportNameTableRVA + expindex *MOM_module_architecture_pointer_size(architecture);	 // VA
				new->dst = desc->ImportAddressTableRVA + expindex *MOM_module_architecture_pointer_size(architecture);	// VA

				if (!handle->delayed_imports) {
					handle->delayed_imports = last = new;
				}
				last = new;
				last->next = new = MEM_callocN(sizeof(ModuleImport), "import-delayed");

				thunk = POINTER_OFFSET(thunk, MOM_module_architecture_pointer_size(architecture));
				funk = POINTER_OFFSET(funk, MOM_module_architecture_pointer_size(architecture));
			}
		}

		if (last != NULL) {
			// This will happen in the unlikely case that the module has no delayed_imports!
			last->next = NULL;
		}

		MEM_SAFE_FREE(directory);
		MEM_SAFE_FREE(new);
	}

	return handle->delayed_imports;
}

/** \} */

/* -------------------------------------------------------------------- */
/** \name Exports
 * { */

fnMOM_module_open_by_file MOM_module_open_by_file = winmom_module_open_by_file;
fnMOM_module_open_by_name MOM_module_open_by_name = winmom_module_open_by_name;
fnMOM_module_open_by_image MOM_module_open_by_image = winmom_module_open_by_image;
fnMOM_module_open_by_address MOM_module_open_by_address = winmom_module_open_by_address;
fnMOM_module_close MOM_module_close = winmom_module_close;
fnMOM_module_address MOM_module_address = winmom_module_address;
fnMOM_module_image_size MOM_module_image_size = NULL;
fnMOM_module_memory_size MOM_module_memory_size = winmom_module_size;
fnMOM_module_architecture MOM_module_architecture = winmom_module_architecture;
fnMOM_module_section_begin MOM_module_section_begin = winmom_module_section_begin;
fnMOM_module_section_name MOM_module_section_name = winmom_module_section_name;
fnMOM_module_section_disk MOM_module_section_disk = winmom_module_section_disk;
fnMOM_module_section_memory MOM_module_section_memory = winmom_module_section_memory;
fnMOM_module_section_size MOM_module_section_size = winmom_module_section_size;
fnMOM_module_export_begin MOM_module_export_begin = winmom_module_export_begin;
fnMOM_module_export_find_by_name MOM_module_export_find_by_name = winmom_module_export_find_by_name;
fnMOM_module_export_find_by_ordinal MOM_module_export_find_by_ordinal = winmom_module_export_find_by_ordinal;
fnMOM_module_export_disk MOM_module_export_disk = winmom_module_export_disk;
fnMOM_module_export_memory MOM_module_export_memory = winmom_module_export_memory;
fnMOM_module_import_begin MOM_module_import_begin = winmom_module_import_begin;
fnMOM_module_import_from_disk MOM_module_import_from_disk = winmom_module_import_from_disk;
fnMOM_module_import_to_disk MOM_module_import_to_disk = winmom_module_import_to_disk;
fnMOM_module_import_from_memory MOM_module_import_from_memory = winmom_module_import_from_memory;
fnMOM_module_import_to_memory MOM_module_import_to_memory = winmom_module_import_to_memory;
fnMOM_module_import_begin MOM_module_import_delayed_begin = winmom_module_import_delayed_begin;

fnMOM_module_header_is_valid MOM_module_header_is_valid = winmom_module_header_is_valid;

/** \} */
