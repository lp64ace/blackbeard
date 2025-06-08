#include "config.h"
#include "native.h"
#include "spoof.h"
#include "thread.h"
#include "proc.h"

#include <tlhelp32.h>

/* -------------------------------------------------------------------- */
/** \name Procedure Native
 * \{ */

BobThread* BOB_thread_open_ex(int id) {
	if (id == GetCurrentThreadId()) {
		return (BobProc *)SPOOF(NULL, OpenThread, PROCESS_ALL_ACCESS, FALSE, id);
	}
	return (BobThread *)OpenThread(0xFFFF, FALSE, id);
}

BobThread *BOB_thread_open_parasite(BobProc *process) {
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (snapshot == INVALID_HANDLE_VALUE) {
		return NULL;
	}

	THREADENTRY32 entry;
	entry.dwSize = sizeof(THREADENTRY32);

	BobThread *thread = BOB_thread_open_most_executed(process);
	for (BOOL ret = (BOOL)SPOOF(NULL, Thread32First, snapshot, &entry); ret; ret = (BOOL)SPOOF(NULL, Thread32Next, snapshot, &entry)) {
		if (entry.th32OwnerProcessID != BOB_process_index(process)) {
			continue;
		}

		BobThread *itr = BOB_thread_open_ex(entry.th32ThreadID);

		if (BOB_thread_time_kernel(itr) + BOB_thread_time_user(itr) > 2.0) {
			double ratio = BOB_thread_time_user(itr) / BOB_thread_time_kernel(itr);
			if (thread == NULL || ratio < (BOB_thread_time_user(thread) / BOB_thread_time_kernel(thread))) {
				thread = itr;
			}
		}
	}

	return thread;
}

BobThread *BOB_thread_open_most_executed(BobProc *process) {
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (snapshot == INVALID_HANDLE_VALUE) {
		return NULL;
	}

	THREADENTRY32 entry;
	entry.dwSize = sizeof(THREADENTRY32);

	BobThread *thread = NULL;
	for (BOOL ret = (BOOL)SPOOF(NULL, Thread32First, snapshot, &entry); ret; ret = (BOOL)SPOOF(NULL, Thread32Next, snapshot, &entry)) {
		if (entry.th32OwnerProcessID != BOB_process_index(process)) {
			continue;
		}

		BobThread *itr = BOB_thread_open_ex(entry.th32ThreadID);

		double old = BOB_thread_time_kernel(thread) + BOB_thread_time_user(thread);
		double now = BOB_thread_time_kernel(itr) + BOB_thread_time_user(itr);
		if (thread == NULL || now > old) {
			thread = itr;
		}
	}

	return thread;
}

BobThread *BOB_thread_open_least_executed(BobProc *process) {
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (snapshot == INVALID_HANDLE_VALUE) {
		return NULL;
	}

	THREADENTRY32 entry;
	entry.dwSize = sizeof(THREADENTRY32);

	BobThread *thread = NULL;
	for (BOOL ret = (BOOL)SPOOF(NULL, Thread32First, snapshot, &entry); ret; ret = (BOOL)SPOOF(NULL, Thread32Next, snapshot, &entry)) {
		if (entry.th32OwnerProcessID != BOB_process_index(process)) {
			continue;
		}

		BobThread *itr = BOB_thread_open_ex(entry.th32ThreadID);

		double old = BOB_thread_time_kernel(thread) + BOB_thread_time_user(thread);
		double now = BOB_thread_time_kernel(itr) + BOB_thread_time_user(itr);
		if (thread == NULL || now < old) {
			thread = itr;
		}
	}

	return thread;
}

bool BOB_thread_suspend(BobThread *thread) {
	return (DWORD)SPOOF(NULL, SuspendThread, thread) != (DWORD)-1;
}
bool BOB_thread_resume(BobThread *thread) {
	return (DWORD)SPOOF(NULL, ResumeThread, thread) != (DWORD)-1;
}
bool BOB_thread_terminate(BobThread *thread) {
	return (BOOL)SPOOF(NULL, TerminateThread, thread, 0);
}
bool BOB_thread_join(BobThread *thread) {
	return (DWORD)SPOOF(NULL, WaitForSingleObject, thread, INFINITE) == WAIT_OBJECT_0;
}
bool BOB_thread_close(BobThread *thread) {
	return (BOOL)SPOOF(NULL, CloseHandle, thread, 0);
}

int BOB_thread_code(BobThread *thread) {
	int exit;
	if ((BOOL)SPOOF(NULL, GetExitCodeThread, thread, &exit)) {
		return exit;
	}
	return 0;
}

BobThread *BOB_thread_new(BobProc *process, void *entry, void *arg) {
	return (BobThread *)SPOOF(NULL, CreateRemoteThread, process, NULL, 0, entry, arg, 0, NULL);
}

bool BOB_thread_execute(BobThread *thread, void *entry) {
	CONTEXT context;
	context.ContextFlags = CONTEXT_CONTROL;

	if (!BOB_thread_suspend(thread)) {
		return false;
	}
	if (!(BOOL)SPOOF(NULL, GetThreadContext, &context)) {
		BOB_thread_resume(thread);
		return false;
	}

#ifdef _WIN64
	context.Rip = entry;
#else
	context.Eip = entry;
#endif

	if (!(BOOL)SPOOF(NULL, SetThreadContext, thread, &context)) {
		BOB_thread_resume(thread);
		return false;
	}

	return BOB_thread_resume(thread);
}

/** \} */

/* -------------------------------------------------------------------- */
/** \name Queries
 * \{ */

int BOB_thread_id(BobThread* thread) {
	return (DWORD)SPOOF(NULL, GetThreadId, (HANDLE)thread);
}

double bob_thread_time(const FILETIME *time) {
	ULARGE_INTEGER integer;
	integer.LowPart = time->dwLowDateTime;
	integer.HighPart = time->dwHighDateTime;
	return ((double)integer.QuadPart) / 1e7;
}

double BOB_thread_time_kernel(const BobThread *thread) {
	FILETIME tspawn, texit, tkernel, tuser;
	if (GetThreadTimes(thread, &tspawn, &texit, &tkernel, &tuser)) {
		return bob_thread_time(&tuser);
	}
	return 0;
}

double BOB_thread_time_user(const BobThread *thread) {
	FILETIME tspawn, texit, tkernel, tuser;
	if (GetThreadTimes(thread, &tspawn, &texit, &tkernel, &tuser)) {
		return bob_thread_time(&tkernel);
	}
	return 0;
}

/** \} */
