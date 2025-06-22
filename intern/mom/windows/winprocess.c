#include "MEM_guardedalloc.h"

#include "intern/mom_internal.h"
#include "mom.h"
#include "winmom.h" // Keep last!

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

HANDLE winmom_process_handle(const ProcessHandle *handle) {
	return (HANDLE)handle->native;
}

LPVOID winmom_process_peb(const ProcessHandle *handle, PEB *peb) {
	PROCESS_BASIC_INFORMATION information;

	HMODULE ntdll = LoadLibrary(_T("ntdll.dll"));
	fnNtQueryInformationProcess _NtQueryInformationProcess = (fnNtQueryInformationProcess)GetProcAddress(ntdll, "NtQueryInformationProcess");
	if (!NT_SUCCESS(_NtQueryInformationProcess(winmom_process_handle(handle), ProcessBasicInformation, &information, sizeof(information), NULL))) {
		return false;
	}
	if (!MOM_process_read(handle, information.PebBaseAddress, peb, sizeof(PEB))) {
		return false;
	}

	return ((PEB *)peb)->Reserved3[1];
}

/** \} */

/* -------------------------------------------------------------------- */
/** \name Process
 * { */

ProcessHandle *winmom_process_open(int identifier) {
	ProcessHandle *handle = MEM_callocN(sizeof(ProcessHandle), "process");
	handle->native = OpenProcess(0xFFFF, FALSE, identifier);

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
			ModuleHandle *module = MOM_module_open_by_address(handle, local.DllBase, local.Reserved3[1]);

			memcpy(module->dllname, FullDllName, MaxLength);
			LIB_addtail(&handle->modules, module);

			total++;
		}
	} while (false);

	return handle;
}

ProcessHandle *winmom_process_self(void) {
	return winmom_process_open(GetCurrentProcessId());
}

void *winmom_process_allocate(ProcessHandle *handle, const void *address, size_t length, int protect) {
	DWORD native = winmom_process_protection_to_native(protect);

	return VirtualAllocEx(winmom_process_handle(handle), address, length, MEM_COMMIT | MEM_RESERVE, native);
}

bool winmom_process_protect(ProcessHandle *handle, const void *address, size_t length, int protect) {
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

int winmom_process_identifier(const ProcessHandle *handle) {
	return GetProcessId(winmom_process_handle(handle));
}

ModuleHandle *winmom_process_module_push(ProcessHandle *handle, ModuleHandle *module) {
	if (MOM_module_name(module)) {
		ModuleHandle *duplicate = MOM_module_open_by_file(MOM_module_name(module));

		if (duplicate) {
			/** Since we use the name to find a module copy the name from the original module! **/
			memcpy(duplicate->dllname, module->dllname, sizeof(duplicate->dllname));
			duplicate->real = module->real;

			LIB_addtail(&handle->modules, duplicate);
		}

		return duplicate;
	}

	return NULL;
}

ModuleHandle *winmom_process_module_find(ProcessHandle *handle, ModuleHandle *module) {
	for (ModuleHandle *itr = MOM_process_module_begin(handle); itr != MOM_process_module_end(handle); itr = MOM_process_module_next(handle, itr)) {
		if (MOM_module_name(module)) {
			if (strcmp(MOM_module_name(module), MOM_module_name(itr)) == 0) {
				return itr;
			}
		}
	}

	return NULL;
}

/** \} */

/* -------------------------------------------------------------------- */
/** \name Exports
 * { */

fnMOM_process_open MOM_process_open = winmom_process_open;
fnMOM_process_self MOM_process_self = winmom_process_self;
fnMOM_process_allocate MOM_process_allocate = winmom_process_allocate;
fnMOM_process_protect MOM_process_protect = winmom_process_protect;
fnMOM_process_write MOM_process_write = winmom_process_write;
fnMOM_process_read MOM_process_read = winmom_process_read;
fnMOM_process_free MOM_process_free = winmom_process_free;
fnMOM_process_close MOM_process_close = winmom_process_close;
fnMOM_process_identifier MOM_process_identifier = winmom_process_identifier;

fnMOM_process_module_push MOM_process_module_push = winmom_process_module_push;
fnMOM_process_module_find MOM_process_module_find = winmom_process_module_find;

/** \} */
