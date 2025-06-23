#include "MEM_guardedalloc.h"

#include "intern/mom_internal.h"
#include "mom.h"
#include "winmom.h" // Keep last!

#include <tlhelp32.h>

/* -------------------------------------------------------------------- */
/** \name Thread Platform Dependent
 * { */

HANDLE winmom_thread_handle(const ThreadHandle *handle) {
	return (HANDLE)handle;
}

/** \} */

/* -------------------------------------------------------------------- */
/** \name Thread
 * { */

ThreadHandle *winmom_thread_open(int identifier) {
	return (ThreadHandle *)OpenThread(0xFFFF, FALSE, identifier);
}

ThreadHandle *winmom_thread_spawn(ProcessHandle *process, void *procedure, void *argument) {
	HANDLE thread;

	fnNtCreateThreadEx _NtCreateThreadEx = (fnNtCreateThreadEx)winmom_resolve_proc("ntdll.dll", "NtCreateThreadEx");
	if (!NT_SUCCESS(_NtCreateThreadEx(&thread, THREAD_ALL_ACCESS, NULL, winmom_process_handle(process), procedure, argument, 0, 0, 0, 0, NULL))) {
		return NULL;
	}

	return (ThreadHandle *)thread;
}

int winmom_thread_identifier(const ThreadHandle *handle) {
	return GetThreadId(winmom_thread_handle(handle));
}

void winmom_thread_close(ThreadHandle *handle) {
	CloseHandle(winmom_thread_handle(handle));
}

bool winmom_thread_queue_apc(ThreadHandle *handle, void *procedure, void *argument) {
	QueueUserAPC(procedure, winmom_thread_handle(handle), (ULONG_PTR)argument);

	return true;
}

bool winmom_thread_terminate(ThreadHandle *handle, int code) {
	return TerminateThread(winmom_thread_handle(handle), code);
}

bool winmom_thread_suspend(ThreadHandle *handle) {
	DWORD count = SuspendThread(winmom_thread_handle(handle));

	return count >= 0;
}

bool winmom_thread_resume(ThreadHandle *handle) {
	DWORD count = ResumeThread(winmom_thread_handle(handle));

	return count >= 0;
}

bool winmom_thread_join(ThreadHandle *handle) {
	return WaitForSingleObject(winmom_thread_handle(handle), INFINITE) == WAIT_OBJECT_0;
}

/** \} */

/* -------------------------------------------------------------------- */
/** \name Exports
 * { */

fnMOM_thread_open MOM_thread_open = winmom_thread_open;
fnMOM_thread_spawn MOM_thread_spawn = winmom_thread_spawn;
fnMOM_thread_close MOM_thread_close = winmom_thread_close;
fnMOM_thread_queue_apc MOM_thread_queue_apc = winmom_thread_queue_apc;
fnMOM_thread_terminate MOM_thread_terminate = winmom_thread_terminate;
fnMOM_thread_join MOM_thread_join = winmom_thread_join;
fnMOM_thread_suspend MOM_thread_suspend = winmom_thread_suspend;
fnMOM_thread_resume MOM_thread_resume = winmom_thread_resume;
fnMOM_thread_identifier MOM_thread_identifier = winmom_thread_identifier;

/** \} */
