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
/** \name Procedure Native
 * \{ */

typedef void *(*fnBobCallbackLdr)(LDR_DATA_TABLE_ENTRY *entry, void *userdata);
typedef void *(*fnBobCallbackSct)(PVOID *entry, UNICODE_STRING *string, void *userdata);
typedef void *(*fnBobCallbackHdr)(PVOID *entry, UNICODE_STRING *string, void *userdata);

BOB_STATIC void *bob_process_loader_enum(struct BobProc *process, fnBobCallbackLdr proc, void *userdata) {
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

BOB_STATIC void *bob_process_section_enum(struct BobProc *process, fnBobCallbackSct proc, void *userdata) {
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

BOB_STATIC void *bob_process_header_enum(struct BobProc *process, fnBobCallbackHdr proc, void *userdata) {
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

struct BobModule *BOB_module_open(struct BobProc *process, const char *name, int search) {
	void *address = NULL;
	do {
		if ((search & SEARCH_LOADER) != 0 && (address = bob_process_loader_enum(process, LdrMatchName, name)) != NULL) {
			break;
		}
		if ((search & SEARCH_HEADER) != 0 && (address = bob_process_header_enum(process, HdrMatchName, name)) != NULL) {
			break;
		}
		if ((search & SEARCH_SECTION) != 0 && (address = bob_process_section_enum(process, SctMatchName, name)) != NULL) {
			break;
		}
	} while (false);
	return (BobModule *)address;
}

void BOB_module_close(struct BobModule *module) {
	(void)module;
}

void *BOB_module_export(struct BobProc *process, struct BobModule *module, const char *target) {
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
				address = POINTER_OFFSET(module, func[ord - exp->Base]);
			}
		}

		for (DWORD i = 0; i < exp->NumberOfNames; i++) {
			char data[256];

			if (!BOB_process_read(process, POINTER_OFFSET(module, name[i]), data, sizeof(data))) {
				continue;
			}

			if (STREQLEN(data, target, 256)) {
				address = POINTER_OFFSET(module, func[ordi[i]]);
			}
		}
		
		if (POINTER_OFFSET(module, image.VirtualAddress) <= address && address <= POINTER_OFFSET(module, image.VirtualAddress + image.Size)) {
			do {
				char forward[255];
				if (!BOB_process_read(process, address, forward, sizeof(forward))) {
					break;
				}

				address = NULL;

				char dll[255];
				char exp[255];

				if (sscanf(forward, "%255[^.].%255s", dll, exp) > 0) {
					char full[255];
					snprintf(full, 255, "%s.dll", dll);

					BobModule *chain = BOB_module_open(process, full, SEARCH_ALL);
					if (chain) {
						if (exp[0] == '#') {
							address = BOB_module_export(process, chain, atoi(exp + 1));
						}
						else {
							address = BOB_module_export(process, chain, exp);
						}
					}
				}
			} while (false);
		}

		HeapFree(GetProcessHeap(), 0, exp);
	}

	return address;
}

/** \} */
