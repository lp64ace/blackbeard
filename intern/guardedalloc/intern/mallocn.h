#ifndef MALLOCN_H
#define MALLOCN_H

#include <stddef.h>
#include <string.h>

#define ALIGNED_MALLOC_MINIMUM_ALIGNMENT sizeof(void *)

#ifdef __cplusplus
extern "C" {
#endif

/* -------------------------------------------------------------------- */
/** \name Platform Specific Wrappers
 * \{ */

/**
 * Allocates memory on a specified alignment boundary.
 *
 * \param[in] size Size of the requested memory allocation.
 * \param[in] alignment The alignment value, which must be an integer power
 * of 2.
 *
 * \return A pointer to the memory block that was allocated or NULL if the
 * operation failed.
 */
void *__aligned_malloc(size_t size, size_t alignment);
/**
 * Frees a block of memory that was allocated with `__aligned_malloc`.
 *
 * \param[in] ptr The pointer to the memory block.
 */
void __aligned_free(void *ptr);

/** \} */

#ifdef __cplusplus
}
#endif

#endif	// MALLOCN_H
