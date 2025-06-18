#ifndef __BOB_PROCESS_H__
#define __BOB_PROCESS_H__

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

/* -------------------------------------------------------------------- */
/** \name Implementation
 * \{ */

typedef struct BobProcess BobProcess;

struct BobProcess *BOB_process_open(int identifier);
struct BobProcess *BOB_process_open_by_name(const char *name);
struct BobProcess *BOB_process_open_by_name_wide(const wchar_t *name);

void *BOB_process_peb(struct BobProcess *process, void *peb);

void BOB_process_close(struct BobProcess *process);

/* \} */

/* -------------------------------------------------------------------- */
/** \name Updates
 * \{ */

enum {
	PROTECT_R = 1 << 0,
	PROTECT_W = 1 << 1,
	PROTECT_E = 1 << 2,
};

void *BOB_process_alloc(struct BobProcess *process, void *address, size_t size, int protection);
size_t BOB_process_read(struct BobProcess *process, const void *address, void *buffer, size_t size);
size_t BOB_process_write(struct BobProcess *process, void *address, const void *buffer, size_t size);
bool BOB_process_free(struct BobProcess *process, void *address, size_t size);

bool BOB_process_protect(struct BobProcess *process, void *address, size_t size, int protection);

/* \} */

/* -------------------------------------------------------------------- */
/** \name Queries
 * \{ */

int BOB_process_identifier(struct BobProcess *process);

bool BOB_process_alive(struct BobProcess *process);

/* \} */

#ifdef __cplusplus
}
#endif

#endif
