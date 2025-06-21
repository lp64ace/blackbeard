#include "config.h"
#include "module.h"
#include "native.h"
#include "process.h"

#include <stdio.h>

#define MIN_ADDRESS (void *)0x10000
#define MAX_ADDRESS (void *)0x7FFFFFFEFFFF

/* -------------------------------------------------------------------- */
/** \name Implementation
 * \{ */

typedef void *(*fnBobCallbackLdr)(LDR_DATA_TABLE_ENTRY *entry, void *userdata);
typedef void *(*fnBobCallbackSct)(PVOID *entry, UNICODE_STRING *string, void *userdata);
typedef void *(*fnBobCallbackHdr)(PVOID *entry, UNICODE_STRING *string, void *userdata);

static inline void *bob_process_loader_enum(BobProcess *process, fnBobCallbackLdr proc, void *userdata) {
	PEB peb;
	PEB_LDR_DATA ldr;
	if (!BOB_process_peb(process, &peb)) {
		return NULL;
	}
	/**
	 * PEB::Ldr already points to a pointer, even through it is not named pLdr!
	 * 
	 * https://www.geoffchappell.com/studies/windows/km/ntoskrnl/inc/api/pebteb/peb/index.htm?tx=179
	 */
	if (!BOB_process_read(process, peb.Ldr, &ldr, sizeof(PEB_LDR_DATA))) {
		return NULL;
	}

	size_t total = 0;

	LIST_ENTRY *head = POINTER_OFFSET(peb.Ldr, FIELD_OFFSET(PEB_LDR_DATA, InMemoryOrderModuleList));
	for (LIST_ENTRY link = ldr.InMemoryOrderModuleList; link.Flink != head; BOB_process_read(process, link.Flink, &link, sizeof(link))) {
		LDR_DATA_TABLE_ENTRY local;

		LDR_DATA_TABLE_ENTRY *remote = CONTAINING_RECORD(link.Flink, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
		if (!(BOOL)BOB_process_read(process, remote, &local, sizeof(local))) {
			continue;
		}

		uint8_t raw[0xBAD];
		if (!(BOOL)BOB_process_read(process, local.FullDllName.Buffer, raw, local.FullDllName.MaximumLength)) {
			continue;
		}
		local.FullDllName.Buffer = (PWSTR)raw;

		void *ret = NULL;
		if ((ret = proc(&local, userdata)) != NULL) {
			return ret;
		}

		total++;
	}

	return NULL;
}

static inline void *bob_process_section_enum(BobProcess *process, fnBobCallbackSct proc, void *userdata) {
	MEMORY_BASIC_INFORMATION information;

	size_t total = 0;

	void *lastbase = NULL;
	for (void *ptr = MIN_ADDRESS; ptr < MAX_ADDRESS; ptr = POINTER_OFFSET(information.BaseAddress, information.RegionSize)) {
		// @todo Make it into a BOB_process_virtual_query function in proc.c!
		if (!(BOOL)bobVirtualQueryEx(process, ptr, &information, sizeof(information))) {
			continue;
		}

		if (information.State != MEM_COMMIT || information.Type != SEC_IMAGE) {
			continue;
		}
		if (information.AllocationBase == lastbase) {
			continue;
		}

		uint8_t name[0xBAD];
		if (!NT_SUCCESS(_NtQueryVirtualMemory(process, information.AllocationBase, 0x2, &name, sizeof(name), NULL))) {
			continue;
		}

		uint8_t raw[0xDAD];
		if (!(BOOL)BOB_process_read(process, information.AllocationBase, raw, sizeof(raw))) {
			continue;
		}

		IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)raw;
		if (dos->e_magic == IMAGE_DOS_SIGNATURE) {
			IMAGE_NT_HEADERS32 *nt32 = POINTER_OFFSET(raw, dos->e_lfanew);
			if (nt32->Signature == IMAGE_NT_SIGNATURE && nt32->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
				void *ret = NULL;
				if ((ret = proc(information.AllocationBase, (UNICODE_STRING *)name, userdata)) != NULL) {
					return ret;
				}
				total++;
			}

			IMAGE_NT_HEADERS64 *nt64 = POINTER_OFFSET(raw, dos->e_lfanew);
			if (nt64->Signature == IMAGE_NT_SIGNATURE && nt64->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
				void *ret = NULL;
				if ((ret = proc(information.AllocationBase, (UNICODE_STRING *)name, userdata)) != NULL) {
					return ret;
				}
				total++;
			}
		}

		lastbase = information.AllocationBase;
	}

	return NULL;
}

static inline void *bob_process_header_enum(BobProcess *process, fnBobCallbackHdr proc, void *userdata) {
	MEMORY_BASIC_INFORMATION information;

	size_t total = 0;

	void *lastbase = NULL;
	for (void *ptr = MIN_ADDRESS; ptr < MAX_ADDRESS; ptr = POINTER_OFFSET(information.BaseAddress, information.RegionSize)) {
		// @todo Make it into a BOB_process_virtual_query function in proc.c!
		if (!(BOOL)bobVirtualQueryEx(process, ptr, &information, sizeof(information))) {
			continue;
		}

		if (information.State != MEM_COMMIT || information.AllocationProtect == PAGE_NOACCESS) {
			continue;
		}
		if ((information.AllocationProtect & PAGE_GUARD) != 0) {
			continue;
		}
		if (information.AllocationBase == lastbase) {
			continue;
		}

		uint8_t name[0xBAD];
		if (!NT_SUCCESS(_NtQueryVirtualMemory(process, information.AllocationBase, 0x2, &name, sizeof(name), NULL))) {
			continue;
		}

		uint8_t raw[0xDAD];
		if (!(BOOL)BOB_process_read(process, information.AllocationBase, raw, sizeof(raw))) {
			continue;
		}

		IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)raw;
		if (dos->e_magic == IMAGE_DOS_SIGNATURE) {
			IMAGE_NT_HEADERS32 *nt32 = POINTER_OFFSET(raw, dos->e_lfanew);
			if (nt32->Signature == IMAGE_NT_SIGNATURE && nt32->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
				void *ret = NULL;
				if ((ret = proc(information.AllocationBase, (UNICODE_STRING *)name, userdata)) != NULL) {
					return ret;
				}
				total++;
			}

			IMAGE_NT_HEADERS64 *nt64 = POINTER_OFFSET(raw, dos->e_lfanew);
			if (nt64->Signature == IMAGE_NT_SIGNATURE && nt64->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
				void *ret = NULL;
				if ((ret = proc(information.AllocationBase, (UNICODE_STRING *)name, userdata)) != NULL) {
					return ret;
				}
				total++;
			}
		}

		lastbase = information.AllocationBase;
	}

	return NULL;
}

static inline void *LdrMatchNameA(LDR_DATA_TABLE_ENTRY *entry, void *name) {
	CHAR FullDllName[MAX_PATH * 4];
	int MaxLength = WideCharToMultiByte(CP_ACP, 0, entry->FullDllName.Buffer, entry->FullDllName.MaximumLength, FullDllName, ARRAYSIZE(FullDllName), 0, NULL);

	for (size_t offset = 0; offset < MaxLength && FullDllName[offset]; offset++) {
		if (FullDllName[offset] == L'\\' || FullDllName[offset] == L'/') {
			if (STRCASEEQ(POINTER_OFFSET(FullDllName, offset + 1), name)) {
				return entry->DllBase;
			}
		}
	}

	return STRCASEEQ(FullDllName, name) ? entry->DllBase : NULL;
}

static inline void *SctMatchNameA(PVOID *entry, UNICODE_STRING *string, void *name) {
	CHAR FullDllName[MAX_PATH * 4];
	int MaxLength = WideCharToMultiByte(CP_ACP, 0, string->Buffer, string->MaximumLength, FullDllName, ARRAYSIZE(FullDllName), 0, NULL);

	for (size_t offset = 0; offset < MaxLength && FullDllName[offset]; offset++) {
		if (FullDllName[offset] == L'\\' || FullDllName[offset] == L'/') {
			if (STRCASEEQ(POINTER_OFFSET(FullDllName, offset + 1), name)) {
				return entry;
			}
		}
	}

	return STRCASEEQ(FullDllName, name) ? entry : NULL;
}

static inline void *HdrMatchNameA(PVOID *entry, UNICODE_STRING *string, void *name) {
	CHAR FullDllName[MAX_PATH * 4];
	int MaxLength = WideCharToMultiByte(CP_ACP, 0, string->Buffer, string->MaximumLength, FullDllName, ARRAYSIZE(FullDllName), 0, NULL);

	for (size_t offset = 0; offset < MaxLength && FullDllName[offset]; offset++) {
		if (FullDllName[offset] == L'\\' || FullDllName[offset] == L'/') {
			if (STRCASEEQ(POINTER_OFFSET(FullDllName, offset + 1), name)) {
				return entry;
			}
		}
	}

	return STRCASEEQ(FullDllName, name) ? entry : NULL;
}

static inline void *LdrMatchNameW(LDR_DATA_TABLE_ENTRY *entry, void *name) {
	for (size_t offset = 0; offset < entry->FullDllName.MaximumLength && entry->FullDllName.Buffer[offset]; offset++) {
		if (entry->FullDllName.Buffer[offset] == L'\\' || entry->FullDllName.Buffer[offset] == L'/') {
			if (_wcsicmp(&entry->FullDllName.Buffer[offset + 1], name) == 0) {
				return entry->DllBase;
			}
		}
	}

	return _wcsicmp(entry->FullDllName.Buffer, name) == 0 ? entry->DllBase : NULL;
}

static inline void *SctMatchNameW(PVOID *entry, UNICODE_STRING *string, void *name) {
	for (size_t offset = 0; offset < string->MaximumLength && string->Buffer[offset]; offset++) {
		if (string->Buffer[offset] == L'\\' || string->Buffer[offset] == L'/') {
			if (_wcsicmp(&string->Buffer[offset + 1], name) == 0) {
				return entry;
			}
		}
	}

	return _wcsicmp(string->Buffer, name) == 0 ? entry : NULL;
}

static inline void *HdrMatchNameW(PVOID *entry, UNICODE_STRING *string, void *name) {
	for (size_t offset = 0; offset < string->MaximumLength && string->Buffer[offset]; offset++) {
		if (string->Buffer[offset] == L'\\' || string->Buffer[offset] == L'/') {
			if (_wcsicmp(&string->Buffer[offset + 1], name) == 0) {
				return entry;
			}
		}
	}

	return _wcsicmp(string->Buffer, name) == 0 ? entry : NULL;
}

BobModule *BOB_module_open_by_name(BobProcess *process, const char *name, int search) {
	void *address = NULL;
	do {
		if ((search & SEARCH_LOADER) != 0 && (address = bob_process_loader_enum(process, LdrMatchNameA, (void *)name)) != NULL) {
			break;
		}
		if ((search & SEARCH_HEADER) != 0 && (address = bob_process_header_enum(process, HdrMatchNameA, (void *)name)) != NULL) {
			break;
		}
		if ((search & SEARCH_SECTION) != 0 && (address = bob_process_section_enum(process, SctMatchNameA, (void *)name)) != NULL) {
			break;
		}
	} while (false);
	return (BobModule *)address;
}

BobModule *BOB_module_open_by_wname(BobProcess *process, const wchar_t *name, int search) {
	void *address = NULL;
	do {
		if ((search & SEARCH_LOADER) != 0 && (address = bob_process_loader_enum(process, LdrMatchNameW, (void *)name)) != NULL) {
			break;
		}
		if ((search & SEARCH_HEADER) != 0 && (address = bob_process_header_enum(process, HdrMatchNameW, (void *)name)) != NULL) {
			break;
		}
		if ((search & SEARCH_SECTION) != 0 && (address = bob_process_section_enum(process, SctMatchNameW, (void *)name)) != NULL) {
			break;
		}
	} while (false);
	return (BobModule *)address;
}

void BOB_module_close(BobModule *module) {
	(void)module;
}

/** \} */

/* -------------------------------------------------------------------- */
/** \name Schema
 * \{ */

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

BobModule *BOB_module_open_by_schema(BobProcess *process, const char *name, int search) {
	PEB *peb = NtCurrentTeb()->ProcessEnvironmentBlock;
	// peb = (PEB *)bobAlloc(sizeof(PEB));
	// if (!BOB_process_peb(process, &peb)) {
	//	return NULL;
	// }

	if (peb->Reserved9[0]) {
		PAPI_SET_NAMESPACE_ARRAY_10 map = (PAPI_SET_NAMESPACE_ARRAY_10)peb->Reserved9[0];

		for (DWORD i = 0; i < map->Count; i++) {
			wchar_t logical[MAX_PATH];
			wchar_t physical[MAX_PATH];

			PAPI_SET_NAMESPACE_ENTRY_10 key = API_SET_NAMESPACE_ARRAY_10_key(map, i);
			PAPI_SET_VALUE_ARRAY_10 value = API_SET_NAMESPACE_ARRAY_10_value(map, key);

			memset(logical, 0, sizeof(logical));
			memcpy(logical, POINTER_OFFSET(map, value->NameOffset), value->NameLength);

			for (DWORD j = 0; j < value->Count; j++) {
				PAPI_SET_VALUE_ENTRY_10 host = API_SET_VALUE_ARRAY_10_entry(value, map, j);

				memset(physical, 0, sizeof(physical));
				memcpy(physical, POINTER_OFFSET(map, host->ValueOffset), host->ValueLength);
				
				CHAR ansi[MAX_PATH];
				int MaxLength = WideCharToMultiByte(CP_ACP, 0, logical, value->NameLength, ansi, ARRAYSIZE(ansi), 0, NULL);

				if (STRCASEEQLEN(ansi, name, value->NameLength / sizeof(wchar_t))) {
					return BOB_module_open_by_wname(process, physical, search);
				}
			}
		}
	}

	return NULL;
}

/** \} */

/* -------------------------------------------------------------------- */
/** \name Query
 * \{ */

void *BOB_module_export(BobProcess *process, BobModule *module, const char *target) {
	uint8_t raw[0x1000];
	if (!BOB_process_read(process, module, raw, sizeof(raw))) {
		return NULL;
	}

	void *address = NULL;

	IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)raw;
	if (dos->e_magic == IMAGE_DOS_SIGNATURE) {
		IMAGE_DATA_DIRECTORY *image;

		IMAGE_NT_HEADERS32 *nt32 = POINTER_OFFSET(raw, dos->e_lfanew);
		if (nt32->Signature == IMAGE_NT_SIGNATURE && nt32->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
			image = &nt32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
		}

		IMAGE_NT_HEADERS64 *nt64 = POINTER_OFFSET(raw, dos->e_lfanew);
		if (nt64->Signature == IMAGE_NT_SIGNATURE && nt64->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
			image = &nt64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
		}

		if (!image->VirtualAddress || !image->Size) {
			return NULL;
		}

		IMAGE_EXPORT_DIRECTORY *exp = bobAlloc(image->Size);

		if (!exp) {
			return NULL;
		}

		if (!BOB_process_read(process, POINTER_OFFSET(module, image->VirtualAddress), exp, image->Size)) {
			bobFree(exp);
			return NULL;
		}

		DWORD *func = POINTER_OFFSET(exp, exp->AddressOfFunctions - image->VirtualAddress);
		DWORD *name = POINTER_OFFSET(exp, exp->AddressOfNames - image->VirtualAddress);
		WORD *ordi = POINTER_OFFSET(exp, exp->AddressOfNameOrdinals - image->VirtualAddress);

		if ((uintptr_t)target <= 0xFFFF) {
			WORD ord = (WORD)POINTER_AS_UINT(target);
			if (ord >= exp->Base && (ord - exp->Base) < exp->NumberOfFunctions) {
				if ((address = POINTER_OFFSET(module, func[ord - exp->Base]))) {
					// break;
				}
			}
		}

		for (DWORD i = 0; i < exp->NumberOfNames; i++) {
			char data[MAX_PATH];

			if (!BOB_process_read(process, POINTER_OFFSET(module, name[i]), data, sizeof(data))) {
				continue;
			}

			if (STREQLEN(data, target, MAX_PATH)) {
				if ((address = POINTER_OFFSET(module, func[ordi[i]]))) {
					break;
				}
			}
		}

		if (POINTER_OFFSET(module, image->VirtualAddress) <= address && address <= POINTER_OFFSET(module, image->VirtualAddress + image->Size)) {
			do {
				char forward[255];
				if (!BOB_process_read(process, address, forward, sizeof(forward))) {
					break;
				}

				address = NULL;

				char dll[MAX_PATH];
				char exp[MAX_PATH];

				if (sscanf(forward, "%255[^.].%255s", dll, exp) > 0) {
					char full[MAX_PATH];
					snprintf(full, sizeof(full), "%s.dll", dll);

					BobModule *chain = NULL;

					do {
						if ((chain = BOB_module_open_by_schema(process, dll, SEARCH_DEFAULT))) {
							break;
						}

						if ((chain = BOB_module_open_by_name(process, dll, SEARCH_DEFAULT))) {
							break;
						}

						if ((chain = BOB_module_open_by_name(process, full, SEARCH_DEFAULT))) {
							break;
						}
					} while (false);

					if (chain) {
						if (exp[0] == '#') {
							if ((address = BOB_module_export(process, chain, POINTER_FROM_INT(atoi(exp + 1))))) {
								break;
							}
						} else {
							if ((address = BOB_module_export(process, chain, exp))) {
								break;
							}
						}
					}
				}
			} while (false);
		}

		bobFree(exp);
	}

	return address;
}

/** \} */
