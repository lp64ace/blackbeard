#include "MEM_guardedalloc.h"

#include "intern/mom_internal.h"
#include "mom.h"
#include "winmom.h" // Keep last!

#include <tlhelp32.h>

typedef struct _MOM_THREAD_BASIC_INFORMATION {
	NTSTATUS ExitStatus;
	PVOID TebBaseAddress;
	CLIENT_ID ClientId;
	ULONG_PTR AffinityMask;
	LONG Priority;
	LONG BasePriority;
} MOM_THREAD_BASIC_INFORMATION, *MOM_PTHREAD_BASIC_INFORMATION;

/* -------------------------------------------------------------------- */
/** \name Thread Platform Dependent
 * { */

HANDLE winmom_thread_handle(const ThreadHandle *handle) {
	return (HANDLE)handle;
}

LPVOID winmom_thread_teb(ProcessHandle *process, ThreadHandle *thread, TEB *teb) {
	MOM_THREAD_BASIC_INFORMATION information;

	fnNtQueryInformationThread _NtQueryInformationThread = (fnNtQueryInformationThread)winmom_resolve_proc("ntdll.dll", "NtQueryInformationThread");
	if (!NT_SUCCESS(_NtQueryInformationThread(winmom_thread_handle(thread), 0, &information, sizeof(information), NULL))) {
		return NULL;
	}
	if (!MOM_process_read(process, information.TebBaseAddress, teb, sizeof(TEB))) {
		return NULL;
	}

	return information.TebBaseAddress;
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

/**
 * This was used when the DLL that we are mapping only contains static TLS data and does not spawn new threads, 
 * when new threads start spawning the static TLS data are not copied over to the other threads!
 */
bool winmom_thread_static_tls_set(ProcessHandle *process, ThreadHandle *thread, int index, const void *data, size_t size) {
	void *address;

	TEB teb;
	if ((address = winmom_thread_teb(process, thread, &teb))) {
		DWORD *entry = ((DWORD *)teb.Reserved1[11]) + index;

		void *allocated;
		if (!(allocated = MOM_process_allocate(process, NULL, size, MOM_PROTECT_R | MOM_PROTECT_W))) {
			return false;
		}
		MOM_process_write(process, allocated, data, size);
		MOM_process_write(process, entry, &allocated, sizeof(allocated));
		return true;
	}

	return false;
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

fnMOM_thread_static_tls_set MOM_thread_static_tls_set = winmom_thread_static_tls_set;

/** \} */
