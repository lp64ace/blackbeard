#ifndef MMAP_H
#define MMAP_H

#include "proc.h"

#ifdef __cplusplus
extern "C" {
#endif

struct BobModule;

/* -------------------------------------------------------------------- */
/** \name Impl
 * \{ */

enum {
	BOB_FORCE_REMAP = 1 << 0,
};

struct BobModule *BOB_mmap_image(struct BobProc *process, const char *path, const void *image, size_t length, int flag);

/** \} */

/* -------------------------------------------------------------------- */
/** \name Queries
 * \{ */

bool BOB_mmap_image_valid(const void *data, size_t length);

/** \} */

#ifdef __cplusplus
}
#endif

#endif