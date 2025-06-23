#ifndef __BOB_MANUALMAP_H__
#define __BOB_MANUALMAP_H__

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#include "mom.h"

#ifdef __cplusplus
extern "C" {
#endif

/* -------------------------------------------------------------------- */
/** \name Implementation
 * \{ */

typedef enum eBobManualMap {
	kBobRebaseAlways = (1 << 0),
	kBobDependency = (1 << 1),
} eBobManualMap;

void *BOB_manual_map_module(struct ProcessHandle *process, struct ModuleHandle *handle, int flag);
void *BOB_manual_map_image(struct ProcessHandle *process, const void *image, size_t size, int flag);

/** \} */

#ifdef __cplusplus
}
#endif

#endif
