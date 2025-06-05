#ifndef PROC_H
#define PROC_H

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

void *BOB_open_process(int pid);
/** The behaviour of this function is undefined when multiple processes have the same name, any can be returned! */
void *BOB_open_process_named(const char *name);

/** Mostly an internal function to get the process information descriptor. */
bool BOB_read_process_information(void *process, void *peb);

#ifdef __cplusplus
}
#endif

#endif
