#include "native.h"

/* -------------------------------------------------------------------- */
/** \name Windows NT Exported Methods
 * \{ */

fnNtQueryInformationProcess _NtQueryInformationProcess;
fnNtQueryVirtualMemory _NtQueryVirtualMemory;
fnNtAlertResumeThread _NtAlertResumeThread;
fnNtCreateThreadEx _NtCreateThreadEx;
fnNtCreateEvent _NtCreateEvent;

void BOB_native_init() {
	HMODULE ntdll = GetModuleHandle("ntdll.dll");
	if (ntdll) {
		_NtQueryInformationProcess = (fnNtQueryInformationProcess)GetProcAddress(ntdll, "NtQueryInformationProcess");
		_NtQueryVirtualMemory = (fnNtQueryVirtualMemory)GetProcAddress(ntdll, "NtQueryVirtualMemory");
		_NtAlertResumeThread = (fnNtAlertResumeThread)GetProcAddress(ntdll, "NtAlertResumeThread");
		_NtCreateThreadEx = (fnNtCreateThreadEx)GetProcAddress(ntdll, "NtCreateThreadEx");
		_NtCreateEvent = (fnNtCreateEvent)GetProcAddress(ntdll, "NtCreateEvent");
	}
}

void BOB_native_exit() {
}

void *(*bobAlloc)(size_t length) = malloc;
void (*bobFree)(void *address) = free;

/** \} */

double BOB_filetime_to_seconds(LPFILETIME time) {
	FILETIME ft;
    
    if (time == NULL) {
        GetSystemTimeAsFileTime(&ft);
		time = &ft;
    }
	
	ULARGE_INTEGER uli;
    uli.LowPart = time->dwLowDateTime;
    uli.HighPart = time->dwHighDateTime;
	
	return (long double)(uli.QuadPart) * 1e-7;
}

/* clang-format off */

LPVOID (*bobVirtualAllocEx)(IN HANDLE process, IN LPVOID address OPTIONAL, IN SIZE_T size, IN DWORD type, IN DWORD protect) = VirtualAllocEx;
BOOL (*bobVirtualFreeEx)(IN HANDLE process, IN LPVOID address, IN SIZE_T size, IN DWORD type) = VirtualFreeEx;
BOOL (*bobVirtualProtectEx)(IN HANDLE process, IN LPVOID address, IN SIZE_T size, IN DWORD protect, OUT PDWORD old) = VirtualProtectEx;
SIZE_T (*bobVirtualQueryEx)(IN HANDLE process, IN LPCVOID address OPTIONAL, OUT PMEMORY_BASIC_INFORMATION buffer, IN SIZE_T size) = VirtualQueryEx;
BOOL (*bobReadProcessMemory)(IN HANDLE process, LPCVOID address, OUT LPVOID buffer, IN SIZE_T size, OUT SIZE_T *read) = ReadProcessMemory;
BOOL (*bobWriteProcessMemory)(IN HANDLE process, LPVOID address, OUT LPCVOID buffer, IN SIZE_T size, OUT SIZE_T *write) = WriteProcessMemory;

HANDLE (*bobCreateRemoteThread)(IN HANDLE process, IN LPSECURITY_ATTRIBUTES attributes, IN SIZE_T stack, IN LPTHREAD_START_ROUTINE address, IN LPVOID param, IN DWORD flags, OUT LPDWORD thread) = CreateRemoteThread;
HANDLE (*bobCreateRemoteThreadEx)(IN HANDLE process, IN LPSECURITY_ATTRIBUTES attributes OPTIONAL, IN SIZE_T stack, IN LPTHREAD_START_ROUTINE address, IN LPVOID param OPTIONAL, IN DWORD flags, IN LPPROC_THREAD_ATTRIBUTE_LIST attr OPTIONAL, OUT LPDWORD thread OPTIONAL) = CreateRemoteThreadEx;
DWORD (*bobQueueUserAPC)(IN PAPCFUNC apc, IN HANDLE thread, IN ULONG_PTR data) = QueueUserAPC;
DWORD (*bobResumeThread)(IN HANDLE thread) = ResumeThread;
DWORD (*bobSuspendThread)(IN HANDLE thread) = SuspendThread;
BOOL (*bobTerminateThread)(IN HANDLE thread, IN DWORD exitcode) = TerminateThread;
// BOOL (*bobGetThreadContext)(IN HANDLE thread, IN OUT LPCONTEXT context) = GetThreadContext;
// BOOL (*bobSetThreadContext)(IN HANDLE thread, IN const CONTEXT *context) = SetThreadContext;

HANDLE (*bobCreateEventA)(IN LPSECURITY_ATTRIBUTES attributes OPTIONAL, IN BOOL manual, IN BOOL initial, IN LPCSTR name OPTIONAL) = CreateEventA;
HANDLE (*bobCreateEventW)(IN LPSECURITY_ATTRIBUTES attributes OPTIONAL, IN BOOL manual, IN BOOL initial, IN LPCWSTR name OPTIONAL) = CreateEventW;
BOOL (*bobDuplicateHandle)(IN HANDLE sprocess, IN HANDLE shandle, IN HANDLE dprocess, OUT LPHANDLE dhandle, IN DWORD access, IN BOOL inherit, IN DWORD options) = DuplicateHandle;

HANDLE (*bobCreateToolhelp32Snapshot)(IN DWORD flags, IN DWORD id) = CreateToolhelp32Snapshot;
BOOL (*bobProcess32First)(IN HANDLE snapshot, IN OUT LPPROCESSENTRY32 lppe) = Process32First;
BOOL (*bobProcess32FirstW)(IN HANDLE snapshot, IN OUT LPPROCESSENTRY32W lppe) = Process32FirstW;
BOOL (*bobProcess32Next)(IN HANDLE snapshot, OUT LPPROCESSENTRY32 lppe) = Process32Next;
BOOL (*bobProcess32NextW)(IN HANDLE snapshot, OUT LPPROCESSENTRY32W lppe) = Process32NextW;
BOOL (*bobThread32First)(IN HANDLE snapshot, IN OUT LPTHREADENTRY32 lpte) = Thread32First;
BOOL (*bobThread32Next)(IN HANDLE snapshot, IN OUT LPTHREADENTRY32 lpte) = Thread32Next;
HANDLE (*bobOpenProcess)(IN DWORD access, IN BOOL inherit, IN DWORD id) = OpenProcess;
HANDLE (*bobOpenThread)(IN DWORD access, IN BOOL inherit, IN DWORD id) = OpenThread;
BOOL (*bobCloseHandle)(IN HANDLE object) = CloseHandle;
DWORD (*bobGetProcessId)(IN HANDLE process) = GetProcessId;
DWORD (*bobGetThreadId)(IN HANDLE process) = GetThreadId;
DWORD (*bobWaitForSingleObject)(IN HANDLE handle, IN DWORD milliseconds) = WaitForSingleObject;
BOOL (*bobGetExitCodeProcess)(IN HANDLE process, OUT PDWORD exitcode) = GetExitCodeProcess;
BOOL (*bobGetExitCodeThread)(IN HANDLE process, OUT PDWORD exitcode) = GetExitCodeThread;
BOOL (*bobGetThreadTimes)(IN HANDLE thread, OUT LPFILETIME tspawn, OUT LPFILETIME texit, OUT LPFILETIME kernel, OUT LPFILETIME user) = GetThreadTimes;

/* clang-format on */
