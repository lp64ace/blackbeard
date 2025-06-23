#include "mallocn_guarded_private.h"
#include "mallocn_lockfree_private.h"
#include "utils/memusage.h"
#include <assert.h>
#include <malloc.h>
#include <stdlib.h>

#ifndef NDEBUG
/** Use guarded allocator on Debug. */
size_t (*MEM_allocN_length)(const void *vptr) = MEM_guarded_allocN_length;
void *(*MEM_mallocN)(size_t size, char const *identity) = MEM_guarded_mallocN;
void *(*MEM_mallocN_aligned)(size_t size, size_t align, char const *identity) = MEM_guarded_mallocN_aligned;
void *(*MEM_callocN)(size_t size, char const *identity) = MEM_guarded_callocN;
void *(*MEM_callocN_aligned)(size_t size, size_t align, char const *identity) = MEM_guarded_callocN_aligned;
void *(*MEM_reallocN_id)(void *vptr, size_t size, char const *identity) = MEM_guarded_reallocN_id;
void *(*MEM_recallocN_id)(void *vptr, size_t size, char const *identity) = MEM_guarded_recallocN_id;
void *(*MEM_dupallocN)(void const *vptr) = MEM_guarded_dupallocN;
void (*MEM_freeN)(void *vptr) = MEM_guarded_freeN;
void (*MEM_print_memlist)() = MEM_guarded_print_memlist;
#else
/** Use lockfree allocator on Release. */
size_t (*MEM_allocN_length)(const void *vptr) = MEM_lockfree_allocN_length;
void *(*MEM_mallocN)(size_t size, char const *identity) = MEM_lockfree_mallocN;
void *(*MEM_mallocN_aligned)(size_t size, size_t align, char const *identity) = MEM_lockfree_mallocN_aligned;
void *(*MEM_callocN)(size_t size, char const *identity) = MEM_lockfree_callocN;
void *(*MEM_callocN_aligned)(size_t size, size_t align, char const *identity) = MEM_lockfree_callocN_aligned;
void *(*MEM_reallocN_id)(void *vptr, size_t size, char const *identity) = MEM_lockfree_reallocN_id;
void *(*MEM_recallocN_id)(void *vptr, size_t size, char const *identity) = MEM_lockfree_recallocN_id;
void *(*MEM_dupallocN)(void const *vptr) = MEM_lockfree_dupallocN;
void (*MEM_freeN)(void *vptr) = MEM_lockfree_freeN;
void (*MEM_print_memlist)() = MEM_lockfree_print_memlist;
#endif

/* -------------------------------------------------------------------- */
/** \name Module Methods
 * \{ */

size_t MEM_num_memory_blocks_in_use() {
	return memory_usage_block_num();
}

size_t MEM_num_memory_in_use() {
	return memory_usage_current();
}

/**
 * Perform assert checks on allocator type change.
 *
 * Helps catching issues (in debug build) caused by an unintended allocator type
 * change when there are allocation happened.
 */
static void assert_for_allocator_change() {
	/* NOTE: Assume that there is no "sticky" internal state which would make
	 * switching allocator type after all allocations are freed unsafe. In fact,
	 * it should be safe to change allocator type after all blocks has been freed:
	 * some regression tests do rely on this property of allocators. */
	assert(MEM_num_memory_blocks_in_use() == 0);
}

void MEM_use_lockfree_allocator(void) {
	/* NOTE: Keep in sync with static initialization of the variables. */

	assert_for_allocator_change();

	MEM_allocN_length = MEM_lockfree_allocN_length;

	MEM_mallocN = MEM_lockfree_mallocN;
	MEM_mallocN_aligned = MEM_lockfree_mallocN_aligned;
	MEM_callocN = MEM_lockfree_callocN;
	MEM_callocN_aligned = MEM_lockfree_callocN_aligned;

	MEM_reallocN_id = MEM_lockfree_reallocN_id;
	MEM_recallocN_id = MEM_lockfree_recallocN_id;

	MEM_dupallocN = MEM_lockfree_dupallocN;

	MEM_freeN = MEM_lockfree_freeN;

	MEM_print_memlist = MEM_lockfree_print_memlist;
}

void MEM_use_guarded_allocator(void) {
	/* NOTE: Keep in sync with static initialization of the variables. */

	assert_for_allocator_change();

	MEM_allocN_length = MEM_guarded_allocN_length;

	MEM_mallocN = MEM_guarded_mallocN;
	MEM_mallocN_aligned = MEM_guarded_mallocN_aligned;
	MEM_callocN = MEM_guarded_callocN;
	MEM_callocN_aligned = MEM_guarded_callocN_aligned;

	MEM_reallocN_id = MEM_guarded_reallocN_id;
	MEM_recallocN_id = MEM_guarded_recallocN_id;

	MEM_dupallocN = MEM_guarded_dupallocN;

	MEM_freeN = MEM_guarded_freeN;

	MEM_print_memlist = MEM_guarded_print_memlist;
}

/** \} */

/* -------------------------------------------------------------------- */
/** \name Platform Specific Wrappers
 * \{ */

void *__aligned_malloc(size_t size, size_t alignment) {
#ifdef _WIN32
	return _aligned_malloc(size, alignment);
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__)
	void *result;

	if (posix_memalign(&result, alignment, size)) {
		/**
		 * non-zero means allocation error
		 * either no allocation or bad alignment value
		 */
		return NULL;
	}
	return result;
#else /* This is for Linux. */
	return memalign(alignment, size);
#endif
}

void __aligned_free(void *ptr) {
#ifdef _WIN32
	_aligned_free(ptr);
#else
	free(ptr);
#endif
}

/** \} */
