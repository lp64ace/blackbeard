#include "config.h"
#include "mod.h"
#include "native.h"
#include "spoof.h"
#include "proc.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

/* -------------------------------------------------------------------- */
/** \name Windows 10
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

BOB_INLINE PAPI_SET_VALUE_ENTRY_10 API_SET_VALUE_ARRAY_10_entry(PAPI_SET_VALUE_ARRAY_10 self, void *map, DWORD i) {
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

BOB_INLINE PAPI_SET_NAMESPACE_ENTRY_10 API_SET_NAMESPACE_ARRAY_10_key(PAPI_SET_NAMESPACE_ARRAY_10 self, DWORD i) {
	return POINTER_OFFSET(self, self->End + i * sizeof(API_SET_NAMESPACE_ENTRY_10));
}

BOB_INLINE PAPI_SET_VALUE_ARRAY_10 API_SET_NAMESPACE_ARRAY_10_value(PAPI_SET_NAMESPACE_ARRAY_10 self, PAPI_SET_NAMESPACE_ENTRY_10 key) {
	return POINTER_OFFSET(self, self->Start + sizeof(API_SET_VALUE_ARRAY_10) * key->Size);
}

/** All of this part needs to be done again properly, with caching and better version managing! */
void BOB_module_api_set_namespace_10(BobProc *process, char *r_name, const char *utf8) {
	PEB *peb = NtCurrentTeb()->ProcessEnvironmentBlock;

	strcpy(r_name, utf8);

	wchar_t name[MAX_PATH];
	int length = MultiByteToWideChar(CP_UTF8, 0, utf8, MAX_PATH, name, MAX_PATH);

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

				if (!_wcsnicmp(logical, name, value->NameLength / sizeof(wchar_t))) {
					WideCharToMultiByte(CP_UTF8, 0, physical, ARRAYSIZE(physical), r_name, MAX_PATH, NULL, NULL);
				}
			}
		}
	}
}

/** \} */

/* -------------------------------------------------------------------- */
/** \name Procedure Native
 * \{ */

typedef void *(*fnBobCallbackLdr)(LDR_DATA_TABLE_ENTRY *entry, void *userdata);
typedef void *(*fnBobCallbackSct)(PVOID *entry, UNICODE_STRING *string, void *userdata);
typedef void *(*fnBobCallbackHdr)(PVOID *entry, UNICODE_STRING *string, void *userdata);

BOB_STATIC void *bob_process_loader_enum(BobProc *process, fnBobCallbackLdr proc, void *userdata) {
	PEB peb;
	PEB_LDR_DATA ldr;
	if (!BOB_process_information(process, &peb)) {
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
	for (LIST_ENTRY link = ldr.InMemoryOrderModuleList; link.Flink != head; SPOOF(NULL, BOB_process_read, process, link.Flink, &link, sizeof(link))) {
		LDR_DATA_TABLE_ENTRY local;

		LDR_DATA_TABLE_ENTRY *remote = CONTAINING_RECORD(link.Flink, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
		if (!(BOOL)SPOOF(NULL, ReadProcessMemory, process, remote, &local, sizeof(local), NULL)) {
			continue;
		}

		uint8_t raw[0xBAD];
		if (!(BOOL)SPOOF(NULL, ReadProcessMemory, process, local.FullDllName.Buffer, raw, local.FullDllName.MaximumLength, NULL)) {
			continue;
		}
		local.FullDllName.Buffer = raw;

		void *ret = NULL;
		if ((ret = proc(&local, userdata)) != NULL) {
			return ret;
		}

		total++;
	}

	return NULL;
}

BOB_STATIC void *bob_process_section_enum(BobProc *process, fnBobCallbackSct proc, void *userdata) {
	MEMORY_BASIC_INFORMATION information;

	size_t total = 0;

	void *lastbase = NULL;
	for (void *ptr = MIN_ADDRESS; ptr < MAX_ADDRESS; ptr = POINTER_OFFSET(information.BaseAddress, information.RegionSize)) {
		// @todo Make it into a BOB_process_virtual_query function in proc.c!
		if (!(BOOL)SPOOF(NULL, VirtualQueryEx, process, ptr, &information, sizeof(information))) {
			continue;
		}

		if (information.State != MEM_COMMIT || information.Type != SEC_IMAGE) {
			continue;
		}
		if (information.AllocationBase == lastbase) {
			continue;
		}

		uint8_t name[0xBAD];
		if (!NT_SUCCESS(SPOOF(NULL, _NtQueryVirtualMemory, process, information.AllocationBase, 0x2, &name, sizeof(name), NULL))) {
			continue;
		}

		uint8_t raw[0xDAD];
		if (!(BOOL)SPOOF(NULL, ReadProcessMemory, process, information.AllocationBase, raw, sizeof(raw), NULL)) {
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

BOB_STATIC void *bob_process_header_enum(BobProc *process, fnBobCallbackHdr proc, void *userdata) {
	MEMORY_BASIC_INFORMATION information;

	size_t total = 0;

	void *lastbase = NULL;
	for (void *ptr = MIN_ADDRESS; ptr < MAX_ADDRESS; ptr = POINTER_OFFSET(information.BaseAddress, information.RegionSize)) {
		// @todo Make it into a BOB_process_virtual_query function in proc.c!
		if (!(BOOL)SPOOF(NULL, VirtualQueryEx, process, ptr, &information, sizeof(information))) {
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
		if (!NT_SUCCESS(SPOOF(NULL, _NtQueryVirtualMemory, process, information.AllocationBase, 0x2, &name, sizeof(name), NULL))) {
			continue;
		}

		uint8_t raw[0xDAD];
		if (!(BOOL)SPOOF(NULL, ReadProcessMemory, process, information.AllocationBase, raw, sizeof(raw), NULL)) {
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

BOB_STATIC void *LdrMatchName(LDR_DATA_TABLE_ENTRY *entry, void *name) {
	CHAR FullDllName[MAX_PATH * 4];
	int MaxLength = WideCharToMultiByte(CP_UTF8, 0, entry->FullDllName.Buffer, entry->FullDllName.MaximumLength, FullDllName, ARRAYSIZE(FullDllName), 0, NULL);

	for (size_t offset = 0; offset < MaxLength && FullDllName[offset]; offset++) {
		if (FullDllName[offset] == L'\\' || FullDllName[offset] == L'/') {
			if (STRCASEEQ(POINTER_OFFSET(FullDllName, offset + 1), name)) {
				return entry->DllBase;
			}
		}
	}

	return STRCASEEQ(FullDllName, name) ? entry->DllBase : NULL;
}

BOB_STATIC void *SctMatchName(PVOID *entry, UNICODE_STRING *string, void *name) {
	CHAR FullDllName[MAX_PATH * 4];
	int MaxLength = WideCharToMultiByte(CP_UTF8, 0, string->Buffer, string->MaximumLength, FullDllName, ARRAYSIZE(FullDllName), 0, NULL);

	for (size_t offset = 0; offset < MaxLength && FullDllName[offset]; offset++) {
		if (FullDllName[offset] == L'\\' || FullDllName[offset] == L'/') {
			if (STRCASEEQ(POINTER_OFFSET(FullDllName, offset + 1), name)) {
				return entry;
			}
		}
	}

	return STRCASEEQ(FullDllName, name) ? entry : NULL;
}

BOB_STATIC void *HdrMatchName(PVOID *entry, UNICODE_STRING *string, void *name) {
	CHAR FullDllName[MAX_PATH * 4];
	int MaxLength = WideCharToMultiByte(CP_UTF8, 0, string->Buffer, string->MaximumLength, FullDllName, ARRAYSIZE(FullDllName), 0, NULL);

	for (size_t offset = 0; offset < MaxLength && FullDllName[offset]; offset++) {
		if (FullDllName[offset] == L'\\' || FullDllName[offset] == L'/') {
			if (STRCASEEQ(POINTER_OFFSET(FullDllName, offset + 1), name)) {
				return entry;
			}
		}
	}

	return STRCASEEQ(FullDllName, name) ? entry : NULL;
}

BobModule *BOB_module_open(BobProc *process, const char *name, int search) {
	char real[MAX_PATH];

	// This works for Windows 10, we need to implement older windows versions!
	BOB_module_api_set_namespace_10(process, real, name);

	void *address = NULL;
	do {
		if ((search & SEARCH_LOADER) != 0 && (address = bob_process_loader_enum(process, LdrMatchName, real)) != NULL) {
			break;
		}
		if ((search & SEARCH_HEADER) != 0 && (address = bob_process_header_enum(process, HdrMatchName, real)) != NULL) {
			break;
		}
		if ((search & SEARCH_SECTION) != 0 && (address = bob_process_section_enum(process, SctMatchName, real)) != NULL) {
			break;
		}
	} while (false);
	return (BobModule *)address;
}

void BOB_module_close(BobModule *module) {
	(void)module;
}

void *BOB_module_export_ex(BobProc *process, BobModule *module, const char *target, char *r_dll, char *r_exp, int maxdepth) {
	uint8_t raw[0xDAD];
	if (!BOB_process_read(process, module, raw, sizeof(raw))) {
		return NULL;
	}

	void *address = NULL;

	IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)raw;
	if (dos->e_magic == IMAGE_DOS_SIGNATURE) {
		IMAGE_DATA_DIRECTORY image;

		memset(&image, 0, sizeof(image));

		IMAGE_NT_HEADERS32 *nt32 = POINTER_OFFSET(raw, dos->e_lfanew);
		if (nt32->Signature == IMAGE_NT_SIGNATURE && nt32->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
			image = nt32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
		}

		IMAGE_NT_HEADERS64 *nt64 = POINTER_OFFSET(raw, dos->e_lfanew);
		if (nt64->Signature == IMAGE_NT_SIGNATURE && nt64->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
			image = nt64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
		}

		if (!image.VirtualAddress || !image.Size) {
			return NULL;
		}

		IMAGE_EXPORT_DIRECTORY *exp = HeapAlloc(GetProcessHeap(), 0, image.Size);

		if (!exp) {
			return NULL;
		}

		if (!BOB_process_read(process, POINTER_OFFSET(module, image.VirtualAddress), exp, image.Size)) {
			HeapFree(GetProcessHeap(), 0, exp);
			return NULL;
		}

		DWORD *func = POINTER_OFFSET(exp, exp->AddressOfFunctions - image.VirtualAddress);
		DWORD *name = POINTER_OFFSET(exp, exp->AddressOfNames - image.VirtualAddress);
		WORD *ordi = POINTER_OFFSET(exp, exp->AddressOfNameOrdinals - image.VirtualAddress);

		if ((uintptr_t)target <= 0xFFFF) {
			WORD ord = (WORD)POINTER_AS_UINT(target);
			if (ord >= exp->Base && (ord - exp->Base) < exp->NumberOfFunctions) {
				if ((address = POINTER_OFFSET(module, func[ord - exp->Base]))) {
					// break;
				}
			}
		}

		for (DWORD i = 0; i < exp->NumberOfNames; i++) {
			char data[256];

			if (!BOB_process_read(process, POINTER_OFFSET(module, name[i]), data, sizeof(data))) {
				continue;
			}

			if (STREQLEN(data, target, 256)) {
				if ((address = POINTER_OFFSET(module, func[ordi[i]]))) {
					break;
				}
			}
		}

		if (POINTER_OFFSET(module, image.VirtualAddress) <= address && address <= POINTER_OFFSET(module, image.VirtualAddress + image.Size)) {
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

					if (r_dll) {
						strncpy(r_dll, dll, MAX_PATH);
					}
					if (r_exp) {
						strncpy(r_exp, exp, MAX_PATH);
					}

					BobModule *chain = NULL;
					
					do {
						if ((chain = BOB_module_open(process, dll, SEARCH_DEFAULT))) {
							break;
						}

						if ((chain = BOB_module_open(process, full, SEARCH_DEFAULT))) {
							break;
						}
					} while (false);

					if (chain) {
						if (exp[0] == '#') {
							if ((address = BOB_module_export_ex(process, chain, atoi(exp + 1), r_dll, r_exp, maxdepth - 1))) {
								break;
							}
						}
						else {
							if ((address = BOB_module_export_ex(process, chain, exp, r_dll, r_exp, maxdepth - 1))) {
								break;
							}
						}
					}
				}
			} while (false);
		}

		HeapFree(GetProcessHeap(), 0, exp);
	}

	return address;
}

void *BOB_module_export(BobProc *process, BobModule *module, const char *target) {
	return BOB_module_export_ex(process, module, target, NULL, NULL, 16);
}

/** \} */
