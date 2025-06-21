#ifndef MEMUSAGE_H
#define MEMUSAGE_H

#include <stdint.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Init the memory usage module.
 */
void memory_usage_init();
/**
 * Called when a new memory block is allocated.
 *
 * \param[in] size The size, in bytes, of the newly allocated memory block.
 */
void memory_usage_block_alloc(size_t const size);
/**
 * Called when a memory block is deallocated.
 *
 * \param[in] size The size, in bytes, of the deallocated memory block.
 */
void memory_usage_block_free(size_t const size);

/**
 * Returns the current allocated memory blocks.
 */
size_t memory_usage_block_num();
/**
 * Returns the current allocated memory in bytes.
 */
size_t memory_usage_current();

/**
 * Get the approximate peak memory usage since the last call to
 * #memory_usage_peak_reset. This is approximate, because the peak usage is not
 * updated after every allocation (see #peak_update_threshold).
 *
 * In the worst case, the peak memory usage is underestimated by
 * `peak_update_threshold * #threads`. After large allocations (larger than the
 * threshold), the peak usage is always updated so those allocations will always
 * be taken into account.
 */
size_t memory_usage_peak();
/**
 * Reset the peak memory usage to the current memory usage.
 */
void memory_usage_peak_reset();

#ifdef __cplusplus
}
#endif

#endif	// MEMUSAGE_H
