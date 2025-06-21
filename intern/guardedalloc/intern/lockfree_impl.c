#include "mallocn.h"
#include "mallocn_lockfree_private.h"
#include "utils/memleak.h"
#include "utils/memusage.h"
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* -------------------------------------------------------------------- */
/** \name Module Utils
 * \{ */

enum {
	MEMHEAD_ALIGN_FLAG = (1 << 0),
};

#define SIZET_ALIGN_4(len) ((len + 3) & ~(size_t)3)

/* Extra padding which needs to be applied on MemHead to make it aligned. */
#define MEMHEAD_ALIGN_PADDING(align) ((size_t)align - (sizeof(LAlignedMemoryHead) % (size_t)align))

/** \} */

/* -------------------------------------------------------------------- */
/** \name Allocation Methods
 * \{ */

size_t MEM_lockfree_allocN_length(const void *vptr) {
	if (vptr) {
		LMemoryHead *head = (LMemoryHead *)vptr;
		--head;
		return head->size;
	}
	return 0;
}

/** \} */

/* -------------------------------------------------------------------- */
/** \name Allocation Methods
 * \{ */

void *MEM_lockfree_mallocN(size_t size, char const *identity) {
	size = SIZET_ALIGN_4(size);

	LMemoryHead *head = malloc(sizeof(LMemoryHead) + size);

	if (head) {
		head->size = size;

#ifndef NDEBUG
		memset(head + 1, 0xff, size);
#endif

		memory_usage_block_alloc(size);

		return (void *)(head + 1);
	}

	return NULL;
}

void *MEM_lockfree_mallocN_aligned(size_t size, size_t align, char const *identity) {
	if (align < ALIGNED_MALLOC_MINIMUM_ALIGNMENT) {
		align = ALIGNED_MALLOC_MINIMUM_ALIGNMENT;
	}

	size_t const pad = MEMHEAD_ALIGN_PADDING(align);

	size = SIZET_ALIGN_4(size);

	LAlignedMemoryHead *head = __aligned_malloc(pad + sizeof(LAlignedMemoryHead) + size, align);

	if (head) {
		head = (LAlignedMemoryHead *)(((char *)head) + pad);

		head->size = size | MEMHEAD_ALIGN_FLAG;
		head->align = align;

#ifndef NDEBUG
		memset(head + 1, 0xff, size);
#endif

		memory_usage_block_alloc(size);

		return (void *)(head + 1);
	}

	return NULL;
}

void *MEM_lockfree_callocN(size_t size, char const *identity) {
	size = SIZET_ALIGN_4(size);

	LMemoryHead *head = malloc(sizeof(LMemoryHead) + size);

	if (head) {
		head->size = size;

		memset(head + 1, 0x00, size);

		memory_usage_block_alloc(size);

		return (void *)(head + 1);
	}

	return NULL;
}

void *MEM_lockfree_callocN_aligned(size_t size, size_t align, char const *identity) {
	if (align < ALIGNED_MALLOC_MINIMUM_ALIGNMENT) {
		align = ALIGNED_MALLOC_MINIMUM_ALIGNMENT;
	}

	size_t const pad = MEMHEAD_ALIGN_PADDING(align);

	size = SIZET_ALIGN_4(size);

	LAlignedMemoryHead *head = __aligned_malloc(pad + sizeof(LAlignedMemoryHead) + size, align);

	if (head) {
		head = (LAlignedMemoryHead *)(((char *)head) + pad);

		head->size = size | MEMHEAD_ALIGN_FLAG;
		head->align = align;

		memset(head + 1, 0x00, size);

		memory_usage_block_alloc(size);

		return (void *)(head + 1);
	}

	return NULL;
}

/** \} */

/* -------------------------------------------------------------------- */
/** \name Reallocation Methods
 * \{ */

void *MEM_lockfree_reallocN_id(void *vptr, size_t size, char const *identity) {
	void *newp = NULL;

	if (vptr) {
		LMemoryHead *head = vptr;
		head--;

		if ((head->size & MEMHEAD_ALIGN_FLAG) == 0) {
			newp = MEM_lockfree_mallocN(size, identity);
		}
		else {
			LAlignedMemoryHead *aligned_head = vptr;
			aligned_head--;

			newp = MEM_lockfree_mallocN_aligned(size, aligned_head->align, identity);
		}

		if (newp) {
			if (size < head->size) {
				/* shrink */
				memcpy(newp, vptr, size);
			}
			else {
				/* grow */
				memcpy(newp, vptr, head->size);
			}

			MEM_lockfree_freeN(vptr);
		}
	}
	else {
		newp = MEM_lockfree_mallocN(size, identity);
	}

	return newp;
}

void *MEM_lockfree_recallocN_id(void *vptr, size_t size, char const *identity) {
	void *newp = NULL;

	if (vptr) {
		LMemoryHead *head = vptr;
		head--;

		if ((head->size & MEMHEAD_ALIGN_FLAG) == 0) {
			newp = MEM_lockfree_mallocN(size, identity);
		}
		else {
			LAlignedMemoryHead *aligned_head = vptr;
			aligned_head--;

			newp = MEM_lockfree_mallocN_aligned(size, aligned_head->align, identity);
		}

		if (newp) {
			if (size < head->size) {
				/* shrink */
				memcpy(newp, vptr, size);
			}
			else {
				/* grow */
				memcpy(newp, vptr, head->size);

				if (size > head->size) {
					/* zero new bytes */
					memset(((char *)newp) + head->size, 0x00, size - head->size);
				}
			}

			MEM_lockfree_freeN(vptr);
		}
	}
	else {
		newp = MEM_lockfree_mallocN(size, identity);
	}

	return newp;
}

/** \} */

/* -------------------------------------------------------------------- */
/** \name Duplication Methods
 * \{ */

void *MEM_lockfree_dupallocN(void const *vptr) {
	void *newp = NULL;

	if (vptr) {
		LMemoryHead const *head = vptr;
		head--;

		do {
			if ((head->size & MEMHEAD_ALIGN_FLAG) == 0) {
				newp = MEM_lockfree_mallocN(head->size, "DupAlloc");
			}
			else {
				LAlignedMemoryHead const *aligned_head = vptr;
				aligned_head--;

				newp = MEM_lockfree_mallocN_aligned(aligned_head->size, aligned_head->align, "DupAlloc");
			}
#ifdef NDEBUG
		} while (newp == NULL);
#else
		} while (false);
#endif

		memcpy(newp, vptr, head->size);
	}

	return newp;
}

/** \} */

/* -------------------------------------------------------------------- */
/** \name Deallocation Methods
 * \{ */

void MEM_lockfree_freeN(void *vptr) {
#ifndef NDEBUG
	if (vptr == NULL) {
		fprintf(stderr, "Attempt to free NULL pointer.\n");
		abort();
		return;
	}

	if (leak_detector_has_run) {
		fprintf(stderr, "%s\n", free_after_leak_detection_message);
		abort();
		return;
	}
#endif

	LMemoryHead *head = vptr;
	head--;

	if ((head->size & MEMHEAD_ALIGN_FLAG) == 0) {
		memory_usage_block_free(head->size);

		free(head);
	}
	else {
		LAlignedMemoryHead *aligned_head = vptr;
		aligned_head--;

		/* Convert to real size and substract from memory usage. */
		aligned_head->size &= ~MEMHEAD_ALIGN_FLAG;
		memory_usage_block_free(aligned_head->size);

		__aligned_free(((char *)aligned_head) - MEMHEAD_ALIGN_PADDING(aligned_head->align));
	}
}

/** \} */

/* -------------------------------------------------------------------- */
/** \name Module Methods
 * \{ */

void MEM_lockfree_print_memlist() {
	fprintf(stdout, "\n*** Unknown Memory List in Lockfree Allocator ***\n");
}

/** \} */
