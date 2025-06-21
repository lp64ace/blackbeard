#include "config.h"
#include "native.h"
#include "process.h"
#include "thread.h"

/* -------------------------------------------------------------------- */
/** \name Implementation
 * \{ */

BobThread *BOB_thread_open(int identifier) {
	return bobOpenThread(0xFFFF, FALSE, identifier);
}

BobThread *BOB_thread_open_by_process(BobProcess *process, int type) {
	HANDLE snapshot = bobCreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);

	THREADENTRY32 entry;
	entry.dwSize = sizeof(THREADENTRY32);

	double criteria = 0;

	int tid = -1;
	for (BOOL ret = bobThread32First(snapshot, &entry); ret; ret = bobThread32Next(snapshot, &entry)) {
		if (BOB_process_identifier(process) != entry.th32OwnerProcessID) {
			continue;
		}
		
		BobThread *thread = BOB_thread_open(entry.th32ThreadID);
		
		switch (type) {
			case THREAD_MAIN: {
				if (criteria > BOB_thread_time_all(thread) || tid < 0) {
					tid = BOB_thread_identifier(thread);
					criteria = BOB_thread_time_all(thread);
				}
			} break;
			case THREAD_MOST: {
				if (criteria > BOB_thread_time_user(thread) || tid < 0) {
					tid = BOB_thread_identifier(thread);
					criteria = BOB_thread_time_user(thread);
				}
			} break;
			case THREAD_LEAST: {
				if (criteria < BOB_thread_time_user(thread) || tid < 0) {
					tid = BOB_thread_identifier(thread);
					criteria = BOB_thread_time_user(thread);
				}
			} break;
		}
		
		BOB_thread_close(thread);
	}

	return BOB_thread_open(tid);
}

BobThread *BOB_thread_new(BobProcess *process, void *procedure, void *argument) {
	BobThread *thread;
	
	if (!NT_SUCCESS(_NtCreateThreadEx(&thread, THREAD_ALL_ACCESS, NULL, process, procedure, argument, 0, 0, 0, 0, NULL))) {
		return NULL;
	}
	
	return thread;
}

void BOB_thread_close(BobThread *thread) {
	bobCloseHandle(thread);
}
 
/** \} */

/* -------------------------------------------------------------------- */
/** \name Queries/Updates
 * \{ */

bool BOB_thread_suspend(BobThread *thread) {
	DWORD count = bobSuspendThread(thread);

	return count >= 0;
}

bool BOB_thread_resume(BobThread *thread) {
	DWORD count = bobResumeThread(thread);

	return count >= 0;
}

bool BOB_thread_join(BobThread *thread) {
	return bobWaitForSingleObject(thread, INFINITE) == WAIT_OBJECT_0;
}

bool BOB_thread_terminate(BobThread *thread, int code) {
	return bobTerminateThread(thread, code) != FALSE;
}

int BOB_thread_exit_code(BobThread *thread) {
	DWORD code;
	
	if (bobGetExitCodeThread(thread, &code)) {
		return code;
	}
	
	return 0;
}

int BOB_thread_identifier(BobThread *thread) {
	return bobGetThreadId(thread);
}

double BOB_thread_time_kernel(BobThread *thread) {
	FILETIME tspawn, texit, tkernel, tuser;
	if (GetThreadTimes(thread, &tspawn, &texit, &tkernel, &tuser)) {
		return BOB_filetime_to_seconds(&tkernel);
	}
	return 0;
}

double BOB_thread_time_user(BobThread *thread) {
	FILETIME tspawn, texit, tkernel, tuser;
	if (GetThreadTimes(thread, &tspawn, &texit, &tkernel, &tuser)) {
		return BOB_filetime_to_seconds(&tuser);
	}
	return 0;
}

double BOB_thread_time_all(BobThread *thread) {
	FILETIME tspawn, texit, tkernel, tuser;
	if (GetThreadTimes(thread, &tspawn, &texit, &tkernel, &tuser)) {
		return BOB_filetime_to_seconds(NULL) - BOB_filetime_to_seconds(&tspawn);
	}
	return 0;
}

/** \} */
