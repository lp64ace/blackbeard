#ifndef __BOB_REMOTE_H__
#define __BOB_REMOTE_H__

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

struct BobProcess;
struct BobThread;

/* -------------------------------------------------------------------- */
/** \name Implementations
 * \{ */

typedef struct BobRemote BobRemote;

struct BobRemote *BOB_remote_open(struct BobProcess *process);

/** The thread is destroyed and the memory released. */
void BOB_remote_close(struct BobRemote *remote);

/** \} */

/* -------------------------------------------------------------------- */
/** \name Remote Execution
 * \{ */

enum {
	NODEREF = 0,
	DEREFPTR,
	DEREFIMM32,
	DEREFIMM64,
};

void BOB_remote_breakpoint(struct BobRemote *remote);
void BOB_remote_push(struct BobRemote *remote, const uint64_t imm, int deref);
void *BOB_remote_write(struct BobRemote *remote, const void *buffer, size_t length);
void *BOB_remote_push_ex(struct BobRemote *remote, const void *buffer, size_t length);
void *BOB_remote_push_ansi(struct BobRemote *remote, const char *ansi);
void *BOB_remote_push_wide(struct BobRemote *remote, const wchar_t *wide);

void BOB_remote_begin64(struct BobRemote *remote);
void BOB_remote_call(struct BobRemote *remote, const void *procedure);
void BOB_remote_fastcall(struct BobRemote *remote, const void *procedure);
void BOB_remote_thiscall(struct BobRemote *remote, const void *procedure);
void BOB_remote_save(struct BobRemote *remote, size_t index);
void BOB_remote_end64(struct BobRemote *remote);

void BOB_remote_notify(struct BobRemote *remote);

uint64_t BOB_remote_invoke(struct BobRemote *remote, void *argument);

/** \} */

/* -------------------------------------------------------------------- */
/** \name Queries
 * \{ */

uint64_t BOB_remote_saved(const struct BobRemote *remote, size_t index);

struct BobThread *BOB_remote_thread(const struct BobRemote *remote);

/** \} */

#ifdef __cplusplus
}
#endif

#endif
