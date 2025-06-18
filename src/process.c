#include "config.h"
#include "process.h"
#include "native.h"

/* -------------------------------------------------------------------- */
/** \name Implementation
 * \{ */

static inline DWORD bob_process_protection_to_native(int protect) {
	if ((protect & PROTECT_R) == 0 && (protect & PROTECT_W) == 0 && (protect & PROTECT_E) == 0) { // 000
		return PAGE_NOACCESS;
	}
	if ((protect & PROTECT_R) == 0 && (protect & PROTECT_W) == 0 && (protect & PROTECT_E) != 0) { // 001
		return PAGE_EXECUTE;
	}
	if ((protect & PROTECT_R) == 0 && (protect & PROTECT_W) != 0 && (protect & PROTECT_E) == 0) { // 010
		return PAGE_WRITECOPY;
	}
	if ((protect & PROTECT_R) == 0 && (protect & PROTECT_W) != 0 && (protect & PROTECT_E) != 0) { // 011
		return PAGE_EXECUTE_WRITECOPY;
	}
	if ((protect & PROTECT_R) != 0 && (protect & PROTECT_W) == 0 && (protect & PROTECT_E) == 0) { // 100
		return PAGE_READONLY;
	}
	if ((protect & PROTECT_R) != 0 && (protect & PROTECT_W) == 0 && (protect & PROTECT_E) != 0) { // 101
		return PAGE_EXECUTE_READ;
	}
	if ((protect & PROTECT_R) != 0 && (protect & PROTECT_W) != 0 && (protect & PROTECT_E) == 0) { // 110
		return PAGE_READWRITE;
	}
	if ((protect & PROTECT_R) != 0 && (protect & PROTECT_W) != 0 && (protect & PROTECT_E) != 0) { // 111
		return PAGE_EXECUTE_READWRITE;
	}
	return PAGE_NOACCESS;
}

BobProcess *BOB_process_open(int identifier) {
	return bobOpenProcess(0xFFFF, FALSE, identifier);
}

BobProcess *BOB_process_open_by_name(const char *name) {
	HANDLE snapshot = bobCreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	PROCESSENTRY32 entry;
	entry.dwSize = sizeof(PROCESSENTRY32);

	int pid = -1;
	for (BOOL ret = bobProcess32First(snapshot, &entry); ret; ret = bobProcess32Next(snapshot, &entry)) {
		if (strcmp(entry.szExeFile, name) == 0) {
			pid = entry.th32ProcessID;
			break;
		}
	}

	return BOB_process_open(pid);
}

BobProcess *BOB_process_open_by_name_wide(const wchar_t *name) {
	HANDLE snapshot = bobCreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	PROCESSENTRY32W entry;
	entry.dwSize = sizeof(PROCESSENTRY32W);

	int pid = -1;
	for (BOOL ret = bobProcess32FirstW(snapshot, &entry); ret; ret = bobProcess32NextW(snapshot, &entry)) {
		if (wcscmp(entry.szExeFile, name) == 0) {
			pid = entry.th32ProcessID;
			break;
		}
	}

	return BOB_process_open(pid);
}

void *BOB_process_peb(struct BobProcess *process, void *peb) {
	PROCESS_BASIC_INFORMATION information;

	if (!NT_SUCCESS(_NtQueryInformationProcess(process, ProcessBasicInformation, &information, sizeof(information), NULL))) {
		return false;
	}
	if (!BOB_process_read(process, information.PebBaseAddress, peb, sizeof(PEB))) {
		return false;
	}

	return ((PEB *)peb)->Reserved3[1];
}

void BOB_process_close(struct BobProcess *process) {
	bobCloseHandle(process);
}

/* \} */

/* -------------------------------------------------------------------- */
/** \name Updates
 * \{ */

void *BOB_process_alloc(struct BobProcess *process, void *address, size_t size, int protection) {
	const DWORD native = bob_process_protection_to_native(protection);

	void *remote = NULL;
	if ((remote = bobVirtualAllocEx((HANDLE)process, address, size, MEM_RESERVE | MEM_COMMIT, native))) {
		return remote;
	}
	// if ((remote = bobVirtualAllocEx((HANDLE)process, address, size, MEM_RESERVE, native))) {
	// 	return remote;
	// }

	return NULL;
}

size_t BOB_process_read(struct BobProcess *process, const void *address, void *buffer, size_t size) {
	SIZE_T read;
	if (bobReadProcessMemory(process, address, buffer, size, &read)) {
		return read;
	}

	return 0;
}

size_t BOB_process_write(struct BobProcess *process, void *address, const void *buffer, size_t size) {
	SIZE_T write;
	if (bobWriteProcessMemory(process, address, buffer, size, &write)) {
		return write;
	}

	return 0;
}

bool BOB_process_free(struct BobProcess *process, void *address, size_t size) {
	// @TODO since we always release, maybe we should remote the size argument!
	if (bobVirtualFreeEx(process, address, size, MEM_RELEASE)) {
		return true;
	}

	return false;
}

bool BOB_process_protect(struct BobProcess *process, void *address, size_t size, int protection) {
	const DWORD native = bob_process_protection_to_native(protection);

	DWORD old;
	if (bobVirtualProtectEx(process, address, size, native, &old)) {
		return true;
	}

	return false;
}

/* \} */

/* -------------------------------------------------------------------- */
/** \name Queries
 * \{ */

int BOB_process_identifier(BobProcess *process) {
	return bobGetProcessId(process);
}

bool BOB_process_alive(BobProcess *process) {
	DWORD code;

	/** Stupid-ass microsoft documentation, it doesn't always return STILL_ACTIVE! */
	if (bobGetExitCodeProcess(process, &code) == STILL_ACTIVE) {
		return true;
	}
	return code == STILL_ACTIVE;
}

/* \} */
