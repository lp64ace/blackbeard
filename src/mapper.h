#ifndef __BOB_MAPPER_H__
#define __BOB_MAPPER_H__

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

struct BobModule;
struct BobProcess;

/* -------------------------------------------------------------------- */
/** \name Implementation
 * \{ */

struct BobModule *BOB_mapper_do(struct BobProcess *process, const wchar_t *path, const void *loaded, size_t size);

/** \} */

#ifdef __cplusplus
}
#endif

#endif
