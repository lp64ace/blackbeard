#include "MEM_guardedalloc.h"

#include "intern/mom_internal.h"
#include "mom.h"
#include "winmom.h" // Keep last!

#include <tlhelp32.h>

/* -------------------------------------------------------------------- */
/** \name Event Platform Specific
 * { */

HANDLE *winmom_event_native(EventHandle *event) {
	return (HANDLE)event;
}

/** \} */

/* -------------------------------------------------------------------- */
/** \name Event
 * { */

EventHandle *winmom_event_open(const char *name) {
	return (EventHandle *)CreateEvent(NULL, TRUE, FALSE, name);
}

void winmom_event_close(EventHandle *event) {
	CloseHandle(winmom_event_native(event));
}

void *winmom_event_share(EventHandle *event, ProcessHandle *process) {
	HANDLE duplicate;
	if (!DuplicateHandle(GetCurrentProcess(), winmom_event_native(event), winmom_process_handle(process), &duplicate, 0, FALSE, DUPLICATE_SAME_ACCESS)) {
		return NULL;
	}
	return (void *)duplicate;
}

void winmom_event_reset(EventHandle *event) {
	ResetEvent(winmom_event_native(event));
}

bool winmom_event_wait(EventHandle *event, int ms) {
	if (WaitForSingleObject(winmom_event_native(event), ms) != WAIT_OBJECT_0) {
		return false;
	}
	return true;
}

/** \} */

/* -------------------------------------------------------------------- */
/** \name Exports
 * { */

fnMOM_event_open MOM_event_open = winmom_event_open;
fnMOM_event_close MOM_event_close = winmom_event_close;
fnMOM_event_native MOM_event_native = winmom_event_native;
fnMOM_event_share MOM_event_share = winmom_event_share;
fnMOM_event_reset MOM_event_reset = winmom_event_reset;
fnMOM_event_wait MOM_event_wait = winmom_event_wait;

/** \} */
