#include "config.h"
#include "native.h"
#include "spoof.h"
#include "proc.h"

#include <tlhelp32.h>

void *BOB_open_process(int pid) {
	const int flag = PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD | PROCESS_SET_QUOTA | PROCESS_TERMINATE | PROCESS_SUSPEND_RESUME | PROCESS_DUP_HANDLE;
	if (pid == GetCurrentProcessId()) {
		return (void *)SPOOF(NULL, OpenProcess, PROCESS_ALL_ACCESS, FALSE, pid);
	}
	return (void *)SPOOF(NULL, OpenProcess, flag, FALSE, pid);
}

void *BOB_open_process_named(const char *name) {
	HANDLE snapshot = (HANDLE)SPOOF(NULL, CreateToolhelp32Snapshot, TH32CS_SNAPPROCESS, 0);
	
	PROCESSENTRY32 entry;
	entry.dwSize = sizeof(PROCESSENTRY32);
	
	int pid = -1;
	for (BOOL ret = (BOOL)SPOOF(NULL, Process32First, snapshot, &entry); ret; ret = (BOOL)SPOOF(NULL, Process32Next, snapshot, &entry)) {
		if (STRCASEEQ(entry.szExeFile, name)) {
			pid = entry.th32ProcessID;
		}
	}
	
	return BOB_open_process(pid);
}

bool BOB_read_process_information(void *process, void *peb) {
	PROCESS_BASIC_INFORMATION information;
	
	if (!NT_SUCCESS((NTSTATUS)SPOOF(NULL, _NtQueryInformationProcess, process, ProcessBasicInformation, &information, sizeof(information), NULL))) {
		return false;
	}
	if (!(BOOL)SPOOF(NULL, ReadProcessMemory, process, information.PebBaseAddress, peb, sizeof(PEB), NULL)) {
		return false;
	}
	return true;
}
