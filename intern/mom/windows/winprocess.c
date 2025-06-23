#include "MEM_guardedalloc.h"

#include "intern/mom_internal.h"
#include "mom.h"
#include "winmom.h" // Keep last!

#include <tlhelp32.h>

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
/** \name Process Platform Dependent
 * { */

static inline DWORD winmom_process_protection_to_native(int protect) {
	if ((protect & kMomProtectRead) == 0 && (protect & kMomProtectWrite) == 0 && (protect & kMomProtectExec) == 0) { // 000
		return PAGE_NOACCESS;
	}
	if ((protect & kMomProtectRead) == 0 && (protect & kMomProtectWrite) == 0 && (protect & kMomProtectExec) != 0) { // 001
		return PAGE_EXECUTE;
	}
	if ((protect & kMomProtectRead) == 0 && (protect & kMomProtectWrite) != 0 && (protect & kMomProtectExec) == 0) { // 010
		return PAGE_WRITECOPY;
	}
	if ((protect & kMomProtectRead) == 0 && (protect & kMomProtectWrite) != 0 && (protect & kMomProtectExec) != 0) { // 011
		return PAGE_EXECUTE_WRITECOPY;
	}
	if ((protect & kMomProtectRead) != 0 && (protect & kMomProtectWrite) == 0 && (protect & kMomProtectExec) == 0) { // 100
		return PAGE_READONLY;
	}
	if ((protect & kMomProtectRead) != 0 && (protect & kMomProtectWrite) == 0 && (protect & kMomProtectExec) != 0) { // 101
		return PAGE_EXECUTE_READ;
	}
	if ((protect & kMomProtectRead) != 0 && (protect & kMomProtectWrite) != 0 && (protect & kMomProtectExec) == 0) { // 110
		return PAGE_READWRITE;
	}
	if ((protect & kMomProtectRead) != 0 && (protect & kMomProtectWrite) != 0 && (protect & kMomProtectExec) != 0) { // 111
		return PAGE_EXECUTE_READWRITE;
	}
	return PAGE_NOACCESS;
}


/**
 * schemanames are absolutely nuts here are some name layouts;
 *  - [EXT-MS-WIN-][Schema-Name-Separated]-L[MajorVersion-MinorVersion](-RevisionVersion)(.dll)
 *  - [API-MS-WIN-][Schema-Name-Separated]-L[MajorVersion-MinorVersion](-RevisionVersion)(.dll)
 */
ListBase winmom_process_resolve_schema(const char *schemaname) {
	ListBase list;
	LIB_listbase_clear(&list);

	PEB peb;
	if (winmom_current_peb(&peb)) {
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

						if (winmom_module_schema_match(wlogical, schemaname)) {
							for (DWORD j = 0; j < value->Count; j++) {
								PAPI_SET_VALUE_ENTRY_10 host = API_SET_VALUE_ARRAY_10_entry(value, map, j);

								memset(wphysical, 0, sizeof(wphysical));
								memcpy(wphysical, POINTER_OFFSET(map, host->ValueOffset), host->ValueLength);

								CHAR physical[MAX_PATH];
								int length = WideCharToMultiByte(CP_ACP, 0, wphysical, -1, physical, ARRAYSIZE(physical), 0, NULL);

								SchemaEntry *entry = MEM_callocN(sizeof(SchemaEntry), "SchemaEntry");
								memcpy(entry->physical, physical, length);
								LIB_addtail(&list, entry);
							}

							break;
						}
					}
				} break;
			}
		} while (false);
	}

	return list;
}

HANDLE winmom_process_handle(ProcessHandle *handle) {
	return (HANDLE)handle->native;
}

LPVOID winmom_process_peb(ProcessHandle *handle, PEB *peb) {
	PROCESS_BASIC_INFORMATION information;

	fnNtQueryInformationProcess _NtQueryInformationProcess = (fnNtQueryInformationProcess)winmom_resolve_proc("ntdll.dll", "NtQueryInformationProcess");
	if (!NT_SUCCESS(_NtQueryInformationProcess(winmom_process_handle(handle), ProcessBasicInformation, &information, sizeof(information), NULL))) {
		return false;
	}
	if (!MOM_process_read(handle, information.PebBaseAddress, peb, sizeof(PEB))) {
		return false;
	}

	return ((PEB *)peb)->Reserved3[1];
}

LPVOID winmom_current_peb(PEB *peb) {
	PROCESS_BASIC_INFORMATION information;

	fnNtQueryInformationProcess _NtQueryInformationProcess = (fnNtQueryInformationProcess)winmom_resolve_proc("ntdll.dll", "NtQueryInformationProcess");
	if (!NT_SUCCESS(_NtQueryInformationProcess(GetCurrentProcess(), ProcessBasicInformation, &information, sizeof(information), NULL))) {
		return false;
	}
	memcpy(peb, information.PebBaseAddress, sizeof(PEB));

	return ((PEB *)peb)->Reserved3[1];
}

/** \} */

/* -------------------------------------------------------------------- */
/** \name Process
 * { */

ListBase winmom_process_open_by_name(const char *name) {
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	PROCESSENTRY32 entry;
	entry.dwSize = sizeof(PROCESSENTRY32);

	ListBase list;
	LIB_listbase_clear(&list);
	for (BOOL ret = Process32First(snapshot, &entry); ret; ret = Process32Next(snapshot, &entry)) {
		if (strcmp(entry.szExeFile, name) == 0) {
			LIB_addtail(&list, MOM_process_open(entry.th32ProcessID));
		}
	}

	return list;
}

ProcessHandle *winmom_process_open(int identifier) {
	ProcessHandle *handle = MEM_callocN(sizeof(ProcessHandle), "ProcessHandle");
	handle->native = (uintptr_t)OpenProcess(0xFFFF, FALSE, identifier);

	do {
		PEB peb;
		PEB_LDR_DATA ldr;
		if (!winmom_process_peb(handle, &peb)) {
			break;
		}
		/**
		 * PEB::Ldr already points to a pointer, even through it is not named pLdr!
		 *
		 * https://www.geoffchappell.com/studies/windows/km/ntoskrnl/inc/api/pebteb/peb/index.htm?tx=179
		 */
		if (!MOM_process_read(handle, peb.Ldr, &ldr, sizeof(PEB_LDR_DATA))) {
			break;
		}

		size_t total = 0;

		LIST_ENTRY *head = POINTER_OFFSET(peb.Ldr, FIELD_OFFSET(PEB_LDR_DATA, InMemoryOrderModuleList));
		for (LIST_ENTRY link = ldr.InMemoryOrderModuleList; link.Flink != head; MOM_process_read(handle, link.Flink, &link, sizeof(link))) {
			LDR_DATA_TABLE_ENTRY local;

			LDR_DATA_TABLE_ENTRY *remote = CONTAINING_RECORD(link.Flink, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
			if (!MOM_process_read(handle, remote, &local, sizeof(local))) {
				continue;
			}

			uint8_t raw[0xBAD];
			if (!MOM_process_read(handle, local.FullDllName.Buffer, raw, local.FullDllName.MaximumLength)) {
				continue;
			}
			local.FullDllName.Buffer = (PWSTR)raw;

			CHAR FullDllName[MAX_PATH * 4];
			int MaxLength = WideCharToMultiByte(CP_ACP, 0, local.FullDllName.Buffer, local.FullDllName.MaximumLength, FullDllName, ARRAYSIZE(FullDllName), 0, NULL);
			ModuleHandle *module = MOM_module_open_by_address(handle, local.DllBase, (size_t)local.Reserved3[1]);
			if (module) {
				memcpy(module->dllname, FullDllName, MaxLength);
			}
			LIB_addtail(&handle->modules, module);

			total++;
		}
	} while (false);

	return handle;
}

ProcessHandle *winmom_process_self(void) {
	return winmom_process_open(GetCurrentProcessId());
}

void *winmom_process_allocate(ProcessHandle *handle, void *address, size_t length, int protect) {
	DWORD native = winmom_process_protection_to_native(protect);

	return VirtualAllocEx(winmom_process_handle(handle), address, length, MEM_COMMIT | MEM_RESERVE, native);
}

bool winmom_process_protect(ProcessHandle *handle, void *address, size_t length, int protect) {
	DWORD native = winmom_process_protection_to_native(protect);
	DWORD oldnative;

	if (!VirtualProtectEx(winmom_process_handle(handle), address, length, native, &oldnative)) {
		return false;
	}

	return true;
}

size_t winmom_process_read(ProcessHandle *handle, const void *address, void *buffer, size_t length) {
	SIZE_T read;
	if (!ReadProcessMemory(winmom_process_handle(handle), address, buffer, length, &read)) {
		return 0;
	}
	return read;
}

size_t winmom_process_write(ProcessHandle *handle, void *address, const void *buffer, size_t length) {
	SIZE_T write;
	if (!WriteProcessMemory(winmom_process_handle(handle), address, buffer, length, &write)) {
		return 0;
	}
	return write;
}

void winmom_process_free(ProcessHandle *handle, void *address) {
	VirtualFreeEx(winmom_process_handle(handle), address, 0, MEM_RELEASE);
}

void winmom_process_close(ProcessHandle *handle) {
	LISTBASE_FOREACH_MUTABLE(ModuleHandle *, module, &handle->modules) {
		MOM_module_close(module);
	}
	LIB_listbase_clear(&handle->modules);

	if (winmom_process_handle(handle)) {
		CloseHandle(winmom_process_handle(handle));
	}

	MEM_SAFE_FREE(handle);
}

int winmom_process_identifier(ProcessHandle *handle) {
	return GetProcessId(winmom_process_handle(handle));
}

ModuleHandle *winmom_process_module_push(ProcessHandle *handle, const ModuleHandle *module) {
	if (MOM_module_name(module)) {
		ListBase duplicates = MOM_module_open_by_file(MOM_module_name(module));

		if (LIB_listbase_is_single(&duplicates)) {
			ModuleHandle *duplicate = (ModuleHandle *)duplicates.first;

			/** Since we use the name to find a module copy the name from the original module! **/
			memcpy(duplicate->dllname, module->dllname, sizeof(duplicate->dllname));
			duplicate->real = module->real;
			LIB_addtail(&handle->modules, duplicate);

			return duplicate;
		}

		return NULL;
	}

	return NULL;
}

ModuleHandle *winmom_process_module_find(ProcessHandle *handle, const ModuleHandle *module) {
	LISTBASE_FOREACH(ModuleHandle *, itr, &handle->modules) {
		if (MOM_module_name(module)) {
			if (strcmp(MOM_module_name(module), MOM_module_name(itr)) == 0) {
				return itr;
			}
		}
	}

	return NULL;
}

ModuleHandle *winmom_process_module_find_by_name(ProcessHandle *handle, const char *name) {
	LISTBASE_FOREACH(ModuleHandle *, itr, &handle->modules) {
		if (winmom_module_loaded_match_name(MOM_module_name(itr), name)) {
			return itr;
		}
	}

	ModuleHandle *module = NULL;

	/**
	 * The following part is the slowest and most unoptimized part of the library!
	 * 
	 * TODO fix that!
	 */

	ListBase schema = winmom_process_resolve_schema(name);
	LISTBASE_FOREACH(SchemaEntry *, entry, &schema) {
		LISTBASE_FOREACH(ModuleHandle *, itr, &handle->modules) {
			if (winmom_module_loaded_match_name(MOM_module_name(itr), entry->physical)) {
				module = itr;
			}
		}
	}
	LIB_freelistN(&schema);

	return module;
}

/** \} */

/* -------------------------------------------------------------------- */
/** \name Exports
 * { */

fnMOM_process_open_by_name MOM_process_open_by_name = winmom_process_open_by_name;
fnMOM_process_open MOM_process_open = winmom_process_open;
fnMOM_process_self MOM_process_self = winmom_process_self;
fnMOM_process_native MOM_process_native = winmom_process_handle;
fnMOM_process_allocate MOM_process_allocate = winmom_process_allocate;
fnMOM_process_protect MOM_process_protect = winmom_process_protect;
fnMOM_process_write MOM_process_write = winmom_process_write;
fnMOM_process_read MOM_process_read = winmom_process_read;
fnMOM_process_free MOM_process_free = winmom_process_free;
fnMOM_process_close MOM_process_close = winmom_process_close;
fnMOM_process_identifier MOM_process_identifier = winmom_process_identifier;

fnMOM_process_module_push MOM_process_module_push = winmom_process_module_push;
fnMOM_process_module_find MOM_process_module_find = winmom_process_module_find;
fnMOM_process_module_find_by_name MOM_process_module_find_by_name = winmom_process_module_find_by_name;

/** \} */

/* -------------------------------------------------------------------- */
/** \name Platform Internals
 * { */

void *winmom_resolve_proc(const char *dllname, const char *procname) {
	HMODULE module;
	if ((module = LoadLibraryA(dllname))) {
		return GetProcAddress(module, procname);
	}
	return NULL;
}

/** \} */
