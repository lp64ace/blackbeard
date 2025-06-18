#ifndef __BOB_NATIVE_H__
#define __BOB_NATIVE_H__

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

/* clang-format off */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h>
#include <tlhelp32.h>

/* clang-format on */

#ifdef __cplusplus
extern "C" {
#endif

/* -------------------------------------------------------------------- */
/** \name Windows NT Exported Methods
 * \{ */

typedef NTSTATUS(NTAPI *fnNtQueryInformationProcess)(IN HANDLE ProcessHandle, IN PROCESSINFOCLASS ProcessInformationClass, OUT PVOID ProcessInformation, IN ULONG ProcessInformationLength, OUT PULONG ReturnLength OPTIONAL);
typedef NTSTATUS(NTAPI *fnNtQueryVirtualMemory)(IN HANDLE ProcessHandle, IN PVOID BaseAddress, IN INT MemoryInformationClass, OUT PVOID MemoryInformation, IN SIZE_T MemoryInformationLength, OUT PSIZE_T ReturnLength);
typedef NTSTATUS(NTAPI *fnNtAlertResumeThread)(IN HANDLE ThreadHandle, OUT PULONG SuspendCount);
typedef NTSTATUS(NTAPI *fnNtCreateThreadEx)(OUT PHANDLE ThreadHandle, IN ACCESS_MASK DesiredAccess, IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL, IN HANDLE ProcessHandle, IN LPVOID Routine, IN PVOID Argument OPTIONAL, IN ULONG CreateFlags, IN SIZE_T ZeroBits, IN SIZE_T StackSize, IN SIZE_T MaximumStackSize, IN LPVOID AttributeList OPTIONAL);
typedef NTSTATUS(NTAPI *fnNtCreateEvent)(OUT HANDLE EventHandle, IN ACCESS_MASK DesiredAccess, IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL, IN INT EventType, IN BOOLEAN InitialState);

extern fnNtQueryInformationProcess _NtQueryInformationProcess;
extern fnNtQueryVirtualMemory _NtQueryVirtualMemory;
extern fnNtAlertResumeThread _NtAlertResumeThread;
extern fnNtCreateThreadEx _NtCreateThreadEx;
extern fnNtCreateEvent _NtCreateEvent;

void BOB_native_init();
void BOB_native_exit();

extern void *(*bobAlloc)(size_t length);
extern void (*bobFree)(void *address);

/** \} */

double BOB_filetime_to_seconds(LPFILETIME time);

/*
 * To reset a single function to its default implementation, you can simply use:
 * \code{.c}
 *     bobVirtualAllocEx = ::VirtualAllocEx // etc.
 * \endcode
 */

/* clang-format off */

extern LPVOID (*bobVirtualAllocEx)(IN HANDLE process, IN LPVOID address OPTIONAL, IN SIZE_T size, IN DWORD type, IN DWORD protect);
extern BOOL (*bobVirtualFreeEx)(IN HANDLE process, IN LPVOID address, IN SIZE_T size, IN DWORD type);
extern BOOL (*bobVirtualProtectEx)(IN HANDLE process, IN LPVOID address, IN SIZE_T size, IN DWORD protect, OUT PDWORD old);
extern SIZE_T (*bobVirtualQueryEx)(IN HANDLE process, IN LPCVOID address OPTIONAL, OUT PMEMORY_BASIC_INFORMATION buffer, IN SIZE_T size);
extern BOOL (*bobReadProcessMemory)(IN HANDLE process, LPCVOID address, OUT LPVOID buffer, IN SIZE_T size, OUT SIZE_T *read);
extern BOOL (*bobWriteProcessMemory)(IN HANDLE process, LPVOID address, OUT LPCVOID buffer, IN SIZE_T size, OUT SIZE_T *write);

extern HANDLE (*bobCreateRemoteThread)(IN HANDLE process, IN LPSECURITY_ATTRIBUTES attributes, IN SIZE_T stack, IN LPTHREAD_START_ROUTINE address, IN LPVOID param, IN DWORD flags, OUT LPDWORD thread);
extern HANDLE (*bobCreateRemoteThreadEx)(IN HANDLE process, IN LPSECURITY_ATTRIBUTES attributes OPTIONAL, IN SIZE_T stack, IN LPTHREAD_START_ROUTINE address, IN LPVOID param OPTIONAL, IN DWORD flags, IN LPPROC_THREAD_ATTRIBUTE_LIST attr OPTIONAL, OUT LPDWORD thread OPTIONAL);
extern DWORD (*bobQueueUserAPC)(IN PAPCFUNC apc, IN HANDLE thread, IN ULONG_PTR data);
extern DWORD (*bobResumeThread)(IN HANDLE thread);
extern DWORD (*bobSuspendThread)(IN HANDLE thread);
extern BOOL (*bobTerminateThread)(IN HANDLE thread, IN DWORD exitcode);
extern BOOL (*bobGetThreadContext)(IN HANDLE thread, IN OUT LPCONTEXT context);
extern BOOL (*bobSetThreadContext)(IN HANDLE thread, IN LPCONTEXT context);

extern HANDLE (*bobCreateEventA)(IN LPSECURITY_ATTRIBUTES attributes OPTIONAL, IN BOOL manual, IN BOOL initial, IN LPCSTR name OPTIONAL);
extern HANDLE (*bobCreateEventW)(IN LPSECURITY_ATTRIBUTES attributes OPTIONAL, IN BOOL manual, IN BOOL initial, IN LPCWSTR name OPTIONAL);
extern BOOL (*bobDuplicateHandle)(IN HANDLE sprocess, IN HANDLE shandle, IN HANDLE dprocess, OUT LPHANDLE dhandle, IN DWORD access, IN BOOL inherit, IN DWORD options);

extern HANDLE (*bobCreateToolhelp32Snapshot)(IN DWORD flags, IN DWORD id);
extern BOOL (*bobProcess32First)(IN HANDLE snapshot, IN OUT LPPROCESSENTRY32 lppe);
extern BOOL (*bobProcess32FirstW)(IN HANDLE snapshot, IN OUT LPPROCESSENTRY32W lppe);
extern BOOL (*bobProcess32Next)(IN HANDLE snapshot, OUT LPPROCESSENTRY32 lppe);
extern BOOL (*bobProcess32NextW)(IN HANDLE snapshot, OUT LPPROCESSENTRY32W lppe);
extern BOOL (*bobThread32First)(IN HANDLE snapshot, IN OUT LPTHREADENTRY32 lpte);
extern BOOL (*bobThread32Next)(IN HANDLE snapshot, IN OUT LPTHREADENTRY32 lpte);
extern HANDLE (*bobOpenProcess)(IN DWORD access, IN BOOL inherit, IN DWORD id);
extern HANDLE (*bobOpenThread)(IN DWORD access, IN BOOL inherit, IN DWORD id);
extern BOOL (*bobCloseHandle)(IN HANDLE object);
extern DWORD (*bobGetProcessId)(IN HANDLE process);
extern DWORD (*bobGetThreadId)(IN HANDLE process);
extern DWORD (*bobWaitForSingleObject)(IN HANDLE handle, IN DWORD milliseconds);
extern BOOL (*bobGetExitCodeProcess)(IN HANDLE process, OUT PDWORD exitcode);
extern BOOL (*bobGetExitCodeThread)(IN HANDLE thread, OUT PDWORD exitcode);
extern BOOL (*bobGetThreadTimes)(IN HANDLE thread, OUT LPFILETIME tspawn, OUT LPFILETIME texit, OUT LPFILETIME kernel, OUT LPFILETIME user);

/* clang-format on */

#ifdef __cplusplus
}
#endif

#endif
