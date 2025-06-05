#include "config.h"
#include "mod.h"
#include "native.h"
#include "spoof.h"
#include "proc.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

BOB_STATIC void bob_translate_module_name(ModuleInformation *module, UNICODE_STRING *name) {
	size_t widelength = name->MaximumLength / sizeof(name->Buffer[0]);
	
	size_t p = 0;
	for (size_t offset = 0; offset < widelength && name->Buffer[offset]; offset++) {
		if (name->Buffer[offset] == L'\\' || name->Buffer[offset] == L'/') {
			p = offset + 1;
		}
	}
	
	WideCharToMultiByte(CP_UTF8, 0, name->Buffer, widelength, module->path, sizeof(module->path), NULL, NULL);
	WideCharToMultiByte(CP_UTF8, 0, name->Buffer + p, widelength - p, module->name, sizeof(module->name), NULL, NULL);
}

BOB_STATIC size_t bob_remote_modules_loader(HANDLE process, ModuleInformation *entries, size_t maxncpy) {
	PEB peb;
	PEB_LDR_DATA ldr;
	
	if (!BOB_read_process_information(process, &peb)) {
		return 0;
	}
	if (!(BOOL)SPOOF(NULL, ReadProcessMemory, process, peb.Ldr, &ldr, sizeof(PEB_LDR_DATA), NULL)) {
		return 0;
	}

	void *head = POINTER_OFFSET(peb.Ldr, FIELD_OFFSET(PEB_LDR_DATA, InMemoryOrderModuleList));
	
	size_t total = 0;
	for (LIST_ENTRY link = ldr.InMemoryOrderModuleList; link.Flink != head; SPOOF(NULL, ReadProcessMemory, process, link.Flink, &link, sizeof(link), NULL)) {
		LDR_DATA_TABLE_ENTRY *remote = CONTAINING_RECORD(link.Flink, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
		LDR_DATA_TABLE_ENTRY local;
		if (!(BOOL)SPOOF(NULL, ReadProcessMemory, process, remote, &local, sizeof(local), NULL)) {
			continue;
		}
		
		uint8_t raw[0xBAD];
		if (total < maxncpy) {
			entries[total].address = local.DllBase;
			entries[total].size = local.Reserved3[1]; // fucking piece of shit is dedacted!
			
			// Rebuild the buffer with local memory!
			if (!(BOOL)SPOOF(NULL, ReadProcessMemory, process, local.FullDllName.Buffer, raw, local.FullDllName.MaximumLength, NULL)) {
				entries[total].path[0] = '\0';
				entries[total].name[0] = '\0';
			}
			else {
				local.FullDllName.Buffer = raw;
				bob_translate_module_name(&entries[total], &local.FullDllName);
			}
		}
		total++;
	}
	return total;
}

BOB_STATIC size_t bob_remote_modules_section(HANDLE process, ModuleInformation *entries, size_t maxncpy) {
	MEMORY_BASIC_INFORMATION information;
	PVOID lastbase = 0;
	
	size_t total = 0;
	for (void *ptr = MIN_ADDRESS; ptr < MAX_ADDRESS; ptr = POINTER_OFFSET(information.BaseAddress, information.RegionSize)) {
		if (!(BOOL)SPOOF(NULL, VirtualQueryEx, process, ptr, &information, sizeof(information))) {
			DWORD error = GetLastError();
			if (error == ERROR_INVALID_PARAMETER) {
				break;
			}
			continue;
		}
		
		if (information.State != MEM_COMMIT || information.Type != SEC_IMAGE) {
			continue;
		}
		if (information.AllocationBase == lastbase) {
			continue;
		}
		lastbase = information.AllocationBase;
		
		uint8_t name[0xBAD];
		if (!NT_SUCCESS(SPOOF(NULL, _NtQueryVirtualMemory, process, information.AllocationBase, 0x2, &name, sizeof(name), NULL))) {
			continue;
		}
		
		uint8_t raw[0x800];
		if (!(BOOL)SPOOF(NULL, ReadProcessMemory, process, information.AllocationBase, raw, sizeof(raw), NULL)) {
			continue;
		}

		IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)raw;
		if (dos->e_magic == IMAGE_DOS_SIGNATURE) {
			IMAGE_NT_HEADERS *nt = POINTER_OFFSET(raw, dos->e_lfanew);
			if (nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR_MAGIC) {
				if (total < maxncpy) {
					entries[total].address = information.AllocationBase;
					entries[total].size = nt->OptionalHeader.SizeOfImage;
					/** Unlike before, address of the name buffer belongs inside the header that we have already read! */
					bob_translate_module_name(&entries[total], (UNICODE_STRING *)name);
				}
				total++;
			}
		}
	}
	return total;
}

BOB_STATIC size_t bob_remote_modules_header(HANDLE process, ModuleInformation *entries, size_t maxncpy) {
	MEMORY_BASIC_INFORMATION information;
	PVOID lastbase = 0;
	
	size_t total = 0;
	for (void *ptr = MIN_ADDRESS; ptr < MAX_ADDRESS; ptr = POINTER_OFFSET(information.BaseAddress, information.RegionSize)) {
		if (!(BOOL)SPOOF(NULL, VirtualQueryEx, process, ptr, &information, sizeof(information))) {
			DWORD error = GetLastError();
			if (error == ERROR_INVALID_PARAMETER) {
				break;
			}
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
		lastbase = information.AllocationBase;
		
		uint8_t raw[0x800];
		if (!(BOOL)SPOOF(NULL, ReadProcessMemory, process, information.AllocationBase, raw, sizeof(raw), NULL)) {
			continue;
		}

		IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)raw;
		if (dos->e_magic == IMAGE_DOS_SIGNATURE) {
			IMAGE_NT_HEADERS *nt = POINTER_OFFSET(raw, dos->e_lfanew);
			if (nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR_MAGIC) {
				if (total < maxncpy) {
					entries[total].address = information.AllocationBase;
					entries[total].size = nt->OptionalHeader.SizeOfImage;
					
					if (!NT_SUCCESS(SPOOF(NULL, _NtQueryVirtualMemory, process, information.AllocationBase, 0x2, raw, sizeof(raw), NULL))) {
						entries[total].path[0] = '\0';
						entries[total].name[0] = '\0';
					}
					else {
						/** Unlike before, address of the name buffer belongs inside the header that we have already read! */
						bob_translate_module_name(&entries[total], (UNICODE_STRING *)raw);
					}
				}
				total++;
			}
		}
	}
	return total;
}

void *BOB_remote_module_address(void *process, const char *name, int search) {
	size_t reserve = 0;
	switch (search) {
		case SEARCH_HEADERS: {
			reserve = bob_remote_modules_header(process, NULL, 0);
		} break;
		case SEARCH_SECTIONS: {
			reserve = bob_remote_modules_section(process, NULL, 0);
		} break;
		case SEARCH_LDR: {
			reserve = bob_remote_modules_loader(process, NULL, 0);
		} break;
	}
	
	ModuleInformation *entries = HeapAlloc(GetProcessHeap(), 0, sizeof(ModuleInformation) * reserve);
	if (!entries) {
		return NULL;
	}
	
	size_t total = 0;
	switch (search) {
		case SEARCH_HEADERS: {
			total = min(reserve, bob_remote_modules_header(process, entries, reserve));
		} break;
		case SEARCH_SECTIONS: {
			total = min(reserve, bob_remote_modules_section(process, entries, reserve));
		} break;
		case SEARCH_LDR: {
			total = min(reserve, bob_remote_modules_loader(process, entries, reserve));
		} break;
	}
	
	void *base = NULL;
	
	for (ModuleInformation *e = entries; e != entries + total; e++) {
		if (STRCASEEQ(e->path, name) || STRCASEEQ(e->name, name)) {
			base = e->address;
		}
	}
	
	return base;
}
