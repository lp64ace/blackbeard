#include "native.h"
#include "spoof.h"

/**
 * This is the only place in the whole module where this is used, and it should stay that way!
 */
#include "xorstr.hh"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>

/* -------------------------------------------------------------------- */
/** \name Windows NT Exported Methods
 * \{ */

fnNtQueryInformationProcess _NtQueryInformationProcess;
fnNtQueryVirtualMemory _NtQueryVirtualMemory;
fnNtCreateThreadEx _NtCreateThreadEx;
fnNtCreateEvent _NtCreateEvent;

/** \} */

void BOB_native_last_error_describe() {
	DWORD error = GetLastError();
	if (error != NO_ERROR) {
		LPSTR text;
		
		DWORD flag = FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_IGNORE_INSERTS;
		if (FormatMessage(flag, NULL, error, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&text, 0, NULL)) {
			fputs(text, stderr);
		}
		LocalFree(text);
	}
}

void BOB_native_init() {
	HMODULE ntdll = (HMODULE)SPOOF(NULL, GetModuleHandle, reinterpret_cast<LPCSTR>(XORSTR("ntdll.dll")));
	if (ntdll) {
		_NtQueryInformationProcess = (fnNtQueryInformationProcess)SPOOF(NULL, GetProcAddress, ntdll, reinterpret_cast<LPCSTR>(XORSTR("NtQueryInformationProcess")));
		_NtQueryVirtualMemory = (fnNtQueryVirtualMemory)SPOOF(NULL, GetProcAddress, ntdll, reinterpret_cast<LPCSTR>(XORSTR("NtQueryVirtualMemory")));
		_NtCreateThreadEx = (fnNtCreateThreadEx)SPOOF(NULL, GetProcAddress, ntdll, reinterpret_cast<LPCSTR>(XORSTR("NtCreateThreadEx")));
		_NtCreateEvent = (fnNtCreateEvent)SPOOF(NULL, GetProcAddress, ntdll, reinterpret_cast<LPCSTR>(XORSTR("NtCreateEvent")));
	}
}

void BOB_native_exit() {
}
