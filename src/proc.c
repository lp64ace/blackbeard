#include "config.h"
#include "native.h"
#include "spoof.h"
#include "proc.h"

#include <tlhelp32.h>

/* -------------------------------------------------------------------- */
/** \name Procedure Native
 * \{ */

BOB_INLINE int bob_process_protection_to_native(int protect) {
	if ((protect & PROTECT_R) == 0 && (protect & PROTECT_W) == 0 && (protect & PROTECT_E) == 0) {  // 000
		return PAGE_NOACCESS;
	}
	if ((protect & PROTECT_R) == 0 && (protect & PROTECT_W) == 0 && (protect & PROTECT_E) != 0) {  // 001
		return PAGE_EXECUTE;
	}
	if ((protect & PROTECT_R) == 0 && (protect & PROTECT_W) != 0 && (protect & PROTECT_E) == 0) {  // 010
		return PAGE_WRITECOPY;
	}
	if ((protect & PROTECT_R) == 0 && (protect & PROTECT_W) != 0 && (protect & PROTECT_E) != 0) {  // 011
		return PAGE_EXECUTE_WRITECOPY;
	}
	if ((protect & PROTECT_R) != 0 && (protect & PROTECT_W) == 0 && (protect & PROTECT_E) == 0) {  // 100
		return PAGE_READONLY;
	}
	if ((protect & PROTECT_R) != 0 && (protect & PROTECT_W) == 0 && (protect & PROTECT_E) != 0) {  // 101
		return PAGE_EXECUTE_READ;
	}
	if ((protect & PROTECT_R) != 0 && (protect & PROTECT_W) != 0 && (protect & PROTECT_E) == 0) {  // 110
		return PAGE_READWRITE;
	}
	if ((protect & PROTECT_R) != 0 && (protect & PROTECT_W) != 0 && (protect & PROTECT_E) != 0) {  // 111
		return PAGE_EXECUTE_READWRITE;
	}
	return PAGE_NOACCESS;
}

void *BOB_process_information(const struct BobProc *process, void *peb) {
	PROCESS_BASIC_INFORMATION information;

	if (!NT_SUCCESS((NTSTATUS)SPOOF(NULL, _NtQueryInformationProcess, (HANDLE)process, ProcessBasicInformation, &information, sizeof(information), NULL))) {
		return false;
	}
	if (!(BOOL)SPOOF(NULL, ReadProcessMemory, process, information.PebBaseAddress, peb, sizeof(PEB), NULL)) {
		return false;
	}

	return ((PEB *)peb)->Reserved3[1]; // Dedacted piece of shit, fucking MSDN %$##3!
}

void *BOB_process_alloc(const struct BobProc *process, const void *address, size_t length, int protect) {
	const int native = bob_process_protection_to_native(protect);

	void *remote = NULL;
	if ((remote = SPOOF(NULL, VirtualAllocEx, (HANDLE)process, address, length, MEM_RESERVE | MEM_COMMIT, native))) {
		return remote;
	}
	if ((remote = SPOOF(NULL, VirtualAllocEx, (HANDLE)process, address, length, MEM_COMMIT, native))) {
		return remote;
	}

	return NULL;
}

void* BOB_process_duplicate(const struct BobProc* process, const void* buffer, size_t length, int protect) {
	void *memory = BOB_process_alloc(process, NULL, length, protect);
	if (memory) {
		if (buffer) {
			if (!BOB_process_write(process, memory, buffer, length)) {
				BOB_process_free(process, memory);
				memory = NULL;
			}
		}
	}
	return memory;
}

bool BOB_process_protect(const struct BobProc *process, const void *address, size_t length, int protect) {
	const int native = bob_process_protection_to_native(protect);

	DWORD old;
	if ((BOOL)SPOOF(NULL, VirtualProtectEx, (HANDLE)process, address, length, native, &old)) {
		return true;
	}

	return false;
}

bool BOB_process_free(const struct BobProc *process, const void *address) {
	if ((BOOL)SPOOF(NULL, VirtualFreeEx, (HANDLE)process, address, 0, MEM_RELEASE)) {
		return true;
	}

	return false;
}

size_t BOB_process_read(const struct BobProc *process, const void *remote, void *local, size_t length) {
	SIZE_T read;
	if (!(BOOL)SPOOF(NULL, ReadProcessMemory, (HANDLE)process, remote, local, length, &read)) {
		return 0;
	}
	return read;
}

size_t BOB_process_write(const struct BobProc *process, const void *remote, const void *local, size_t length) {
	SIZE_T write;
	if (!(BOOL)SPOOF(NULL, WriteProcessMemory, (HANDLE)process, remote, local, length, &write)) {
		return 0;
	}
	return write;
}

struct BobProc *BOB_process_open(const char *name) {
	HANDLE snapshot = (HANDLE)SPOOF(NULL, CreateToolhelp32Snapshot, TH32CS_SNAPPROCESS, 0);

	PROCESSENTRY32W entry;
	entry.dwSize = sizeof(PROCESSENTRY32W);

	int pid = -1;
	for (BOOL ret = (BOOL)SPOOF(NULL, Process32FirstW, snapshot, &entry); ret; ret = (BOOL)SPOOF(NULL, Process32NextW, snapshot, &entry)) {
		CHAR szExeFile[MAX_PATH * 4];
		WideCharToMultiByte(CP_UTF8, 0, entry.szExeFile, MAX_PATH, szExeFile, ARRAYSIZE(szExeFile), 0, NULL);
		if (STRCASEEQ(szExeFile, name)) {
			pid = entry.th32ProcessID;
		}
	}

	return BOB_process_open_ex(pid);
}

struct BobProc *BOB_process_open_ex(int id) {
	if (id == GetCurrentProcessId()) {
		return (BobProc *)SPOOF(NULL, OpenProcess, PROCESS_ALL_ACCESS, FALSE, id);
	}
	return (BobProc *)SPOOF(NULL, OpenProcess, 0xFFFF, FALSE, id);
}

struct BobProc *BOB_process_self(void) {
	return (BobProc *)SPOOF(NULL, GetCurrentProcess);
}

void BOB_process_close(struct BobProc *process) {
	SPOOF(NULL, CloseHandle, process);
}

/** \} */

/* -------------------------------------------------------------------- */
/** \name Queries
 * \{ */

void *BOB_process_address(const struct BobProc *process) {
	PEB peb;
	/** The BOB_process_information already does exactly that, no need to rewrite it! */
	return BOB_process_information(process, &peb);
}
void *BOB_process_handle(const struct BobProc *process) {
	return (HANDLE)process;
}

int BOB_process_index(const struct BobProc *process) {
	return GetProcessId((HANDLE)process);
}

/** \} */
