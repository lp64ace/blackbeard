#ifndef THREAD_H
#define THREAD_H

#include "proc.h"

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct BobThread BobThread;

/* -------------------------------------------------------------------- */
/** \name Procedure Native
 * \{ */

BobThread *BOB_thread_open_ex(int id);

BobThread *BOB_thread_open_parasite(BobProc *process);
BobThread *BOB_thread_open_most_executed(BobProc *process);
BobThread *BOB_thread_open_least_executed(BobProc *process);

BobThread *BOB_thread_new(BobProc *process, void *entry, void *arg);

bool BOB_thread_suspend(BobThread *thread);
bool BOB_thread_resume(BobThread *thread);
bool BOB_thread_terminate(BobThread *thread);
bool BOB_thread_join(BobThread *thread);
bool BOB_thread_close(BobThread *thread);

int BOB_thread_code(BobThread *thread);

/** Take controll of the remote thread and execute usercode! */
bool BOB_thread_execute(BobThread *thread, void *entry);

/** \} */

/* -------------------------------------------------------------------- */
/** \name Queries
 * \{ */

int BOB_thread_id(BobThread *thread);

double BOB_thread_time_kernel(const BobThread *thread);
double BOB_thread_time_user(const BobThread *thread);

/** \} */

#ifdef __cplusplus
}
#endif

#endif
