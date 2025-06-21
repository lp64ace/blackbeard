#include "MEM_guardedalloc.h"

#include "intern/mom_internal.h"
#include "mom.h"
#include "winmom.h" // Keep last!

/* -------------------------------------------------------------------- */
/** \name Process Platform Dependent
 * { */

HANDLE winmom_process_handle(const ProcessHandle *handle) {
	return (HANDLE)handle;
}

LPVOID winmom_process_peb(const ProcessHandle *handle, PEB *peb) {
	PROCESS_BASIC_INFORMATION information;

	HMODULE ntdll = LoadLibrary(_T("ntdll.dll"));
	fnNtQueryInformationProcess _NtQueryInformationProcess = GetProcAddress(ntdll, "NtQueryInformationProcess");
	if (!NT_SUCCESS(_NtQueryInformationProcess(winmom_process_handle(handle), ProcessBasicInformation, &information, sizeof(information), NULL))) {
		return false;
	}
	if (!winmom_process_read(handle, information.PebBaseAddress, peb, sizeof(PEB))) {
		return false;
	}

	return ((PEB *)peb)->Reserved3[1];
}

DWORD winmom_process_read(const ProcessHandle *handle, const void *address, void *buffer, size_t length) {
	SIZE_T read;
	if (!ReadProcessMemory(winmom_process_handle(handle), address, buffer, length, &read)) {
		return 0;
	}
	return read;
}

/** \} */

/* -------------------------------------------------------------------- */
/** \name Process
 * { */

ProcessHandle *winmom_process_open(int identifier) {
	return (ProcessHandle *)OpenProcess(0xFFFF, FALSE, identifier);
}

ProcessHandle *winmom_process_self() {
	return winmom_process_open(GetCurrentProcessId());
}

void winmom_process_close(ProcessHandle *handle) {
	CloseHandle(winmom_process_handle(handle));
}

int winmom_process_identifier(const ProcessHandle *handle) {
	return GetProcessId(winmom_process_handle(handle));
}

/** \} */

/* -------------------------------------------------------------------- */
/** \name Exports
 * { */

fnMOM_process_open MOM_process_open = winmom_process_open;
fnMOM_process_self MOM_process_self = winmom_process_self;
fnMOM_process_close MOM_process_close = winmom_process_close;
fnMOM_process_identifier MOM_process_identifier = winmom_process_identifier;

/** \} */
