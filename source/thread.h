#ifndef __BOB_THREAD_H__
#define __BOB_THREAD_H__

#ifdef __cplusplus
extern "C" {
#endif

struct BobProcess;

/* -------------------------------------------------------------------- */
/** \name Implementation
 * \{ */

typedef struct BobThread BobThread;

enum {
	THREAD_MAIN,
	THREAD_MOST,
	THREAD_LEAST,
};

struct BobThread *BOB_thread_open(int identifier);
struct BobThread *BOB_thread_open_by_process(struct BobProcess *process, int type);
struct BobThread *BOB_thread_new(struct BobProcess *process, void *procedure, void *argument);
 
void BOB_thread_close(struct BobThread *thread);
 
/** \} */

/* -------------------------------------------------------------------- */
/** \name Queries/Updates
 * \{ */

bool BOB_thread_suspend(struct BobThread *thread);
bool BOB_thread_resume(struct BobThread *thread);
bool BOB_thread_join(struct BobThread *thread);
bool BOB_thread_terminate(struct BobThread *thread, int code);

int BOB_thread_exit_code(struct BobThread *thread);
int BOB_thread_identifier(struct BobThread *thread);

double BOB_thread_time_kernel(struct BobThread *thread);
double BOB_thread_time_user(struct BobThread *thread);
double BOB_thread_time_all(struct BobThread *thread);

/** \} */

#ifdef __cplusplus
}
#endif

#endif
