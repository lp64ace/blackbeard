#ifndef REMOTE_H
#define REMOTE_H

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

/**
 * This is absolute fucking horseshit and needs to be cleaned the fuck up!
 * Oh the other hand this is one of the few fucking parts that actually work 
 * in this shit so keep it as is till we fix the rest!
 */

#ifdef __cplusplus
extern "C" {
#endif

struct BobProc;
struct BobModule;

/* -------------------------------------------------------------------- */
/** \name Impl
 * \{ */

typedef struct BobRemote BobRemote;

enum {
	REMOTE_NEW,
	REMOTE_LEASTEXEC,
	REMOTE_MOSTEXEC,
};

enum {
	REMOTE_WIN64,
	REMOTE_CDECL,
	REMOTE_STDCALL,
	REMOTE_FASTCALL,
	REMOTE_THISCALL,
};

struct BobRemote *BOB_remote_open(struct BobProc *process, bool x64);

void *BOB_remote_write(struct BobRemote *remote, const void *data, size_t size);
void *BOB_remote_push(struct BobRemote *remote, const void *data, size_t size);
void BOB_remote_push_int(struct BobRemote *remote, int arg);
void BOB_remote_push_ptr(struct BobRemote *remote, const void *arg);
void *BOB_remote_push_str(struct BobRemote *remote, const char *arg);
void *BOB_remote_push_wstr(struct BobRemote *remote, const wchar_t *arg);
void BOB_remote_push_ref(struct BobRemote *remote, const void *arg);
void BOB_remote_push_ref4(struct BobRemote *remote, const void *arg);
void BOB_remote_push_ref8(struct BobRemote *remote, const void *arg);

void BOB_remote_notify(struct BobRemote *remote);
void BOB_remote_begin_call64(struct BobRemote *remote);
void BOB_remote_call(struct BobRemote *remote, int convention, const void *proc);
void BOB_remote_end_call64(struct BobRemote *remote);
void BOB_remote_exit(struct BobRemote *remote);

void BOB_remote_save(struct BobRemote *remote, int idx);

uint64_t BOB_remote_exec(struct BobRemote *remote, void *arg);

void BOB_remote_close(struct BobRemote *remote);

/** \} */

/* -------------------------------------------------------------------- */
/** \name Queries
 * \{ */

uint64_t BOB_remote_saved(struct BobRemote *remote, int idx);

int BOB_remote_thread_index(struct BobRemote *remote);

/** \} */

#ifdef __cplusplus
}
#endif

#endif