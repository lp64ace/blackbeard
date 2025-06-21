#include "mallocn.h"
#include "mallocn_guarded_private.h"
#include "utils/memleak.h"
#include "utils/memusage.h"

#include <ctype.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* -------------------------------------------------------------------- */
/** \name Private Utils
 * \{ */

ListBase *membase() {
	static ListBase _membase = {NULL, NULL};
	return &_membase;
}

static pthread_mutex_t *mem_thread() {
	static pthread_mutex_t _thread_lock = PTHREAD_MUTEX_INITIALIZER;
	return &_thread_lock;
}

static void mem_lock_thread() {
	pthread_mutex_lock(mem_thread());
}

static void mem_unlock_thread() {
	pthread_mutex_unlock(mem_thread());
}

/** \} */

/* -------------------------------------------------------------------- */
/** \name Module Utils
 * \{ */

#define MAKE_WORD(a, b, c, d) ((((int)(a)) << 24) | (((int)(b)) << 16) | (((int)(c)) << 8) | (((int)(d))))

#define MEMTAG1 MAKE_WORD('M', 'E', 'M', 'O')
#define MEMTAG2 MAKE_WORD('R', 'Y', 'B', 'L')
#define MEMTAG3 MAKE_WORD('O', 'C', 'K', '!')
#define MEMFREE MAKE_WORD('F', 'R', 'E', 'E')

/** Returns the #Link from a #GMemoryHead. */
#define MEMLINK(head) (Link *)(((char *)(head)) + offsetof(GMemoryHead, prev))

/* Extra padding which needs to be applied on MemHead to make it aligned. */
#define MEMHEAD_ALIGN_PADDING(align) ((size_t)align - (sizeof(GMemoryHead) % (size_t)align))

/**
 * Called after memory allocation to intialize the memory block,
 * register it in the memory list and update memory usage accordingly.
 */
static void memhead_init(void *vhead, size_t size, size_t align, char const *identity) {
	GMemoryHead *head = vhead;

	head->tag1 = MEMTAG1;

	head->identity = identity;
	head->size = size;
	head->align = align;

	head->tag2 = MEMTAG2;

	GMemoryTail *tail = (GMemoryTail *)((char *)(head + 1) + head->size);

	tail->tag3 = MEMTAG3;

	memory_usage_block_alloc(head->size);

	mem_lock_thread();

	addlink(membase(), MEMLINK(head));

	mem_unlock_thread();
}

/**
 * Called before memory deallocation to remove it from the memory list and
 * update memory usage accordingly.
 */
static void memhead_exit(void *vhead) {
	GMemoryHead *head = vhead;

	head->tag1 = MEMFREE;
	head->tag2 = MEMFREE;

	GMemoryTail *tail = (GMemoryTail *)((char *)(head + 1) + head->size);

	tail->tag3 = MEMFREE;

	mem_lock_thread();

	remlink(membase(), MEMLINK(head));

	mem_unlock_thread();

	memory_usage_block_free(head->size);
}

/** \} */

/* -------------------------------------------------------------------- */
/** \name Allocation Methods
 * \{ */

void *MEM_guarded_mallocN(size_t size, char const *identity) {
	size_t const total = sizeof(GMemoryHead) + size + sizeof(GMemoryTail);

	GMemoryHead *head = malloc(total);

	if (head) {
		memhead_init(head, size, (size_t)0, identity);
		head++;

#ifndef NDEBUG
		memset(head, 0xff, size);
#endif
	}

	return head;
}

void *MEM_guarded_mallocN_aligned(size_t size, size_t align, char const *identity) {
	if (align < ALIGNED_MALLOC_MINIMUM_ALIGNMENT) {
		align = ALIGNED_MALLOC_MINIMUM_ALIGNMENT;
	}

	size_t const pad = MEMHEAD_ALIGN_PADDING(align);
	size_t const total = pad + sizeof(GMemoryHead) + size + sizeof(GMemoryTail);

	GMemoryHead *head = __aligned_malloc(total, align);

	if (head) {
		head = (GMemoryHead *)(((char *)head) + pad);

		memhead_init(head, size, align, identity);
		head++;

#ifndef NDEBUG
		memset(head, 0xff, size);
#endif
	}

	return head;
}

void *MEM_guarded_callocN(size_t size, char const *identity) {
	size_t const total = sizeof(GMemoryHead) + size + sizeof(GMemoryTail);

	GMemoryHead *head = malloc(total);

	if (head) {
		memhead_init(head, size, (size_t)0, identity);
		head++;

		memset(head, 0x00, size);
	}

	return head;
}

void *MEM_guarded_callocN_aligned(size_t size, size_t align, char const *identity) {
	if (align < ALIGNED_MALLOC_MINIMUM_ALIGNMENT) {
		align = ALIGNED_MALLOC_MINIMUM_ALIGNMENT;
	}

	size_t const pad = MEMHEAD_ALIGN_PADDING(align);
	size_t const total = pad + sizeof(GMemoryHead) + size + sizeof(GMemoryTail);

	GMemoryHead *head = __aligned_malloc(total, align);

	if (head) {
		head = (GMemoryHead *)(((char *)head) + pad);

		memhead_init(head, size, align, identity);
		head++;

		memset(head, 0x00, size);
	}

	return head;
}

/** \} */

/* -------------------------------------------------------------------- */
/** \name Reallocation Methods
 * \{ */

void *MEM_guarded_reallocN_id(void *vptr, size_t size, char const *identity) {
	void *newp = NULL;

	if (vptr) {
		GMemoryHead *head = vptr;
		head--;

		if (head->align == 0) {
			newp = MEM_guarded_mallocN(size, identity);
		}
		else {
			newp = MEM_guarded_mallocN_aligned(size, head->align, identity);
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

			MEM_guarded_freeN(vptr);
		}
	}
	else {
		newp = MEM_guarded_mallocN(size, identity);
	}

	return newp;
}

void *MEM_guarded_recallocN_id(void *vptr, size_t size, char const *identity) {
	void *newp = NULL;

	if (vptr) {
		GMemoryHead *head = vptr;
		head--;

		if (head->align == 0) {
			newp = MEM_guarded_mallocN(size, (head->identity) ? head->identity : identity);
		}
		else {
			newp = MEM_guarded_mallocN_aligned(size, head->align, (head->identity) ? head->identity : identity);
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

			MEM_guarded_freeN(vptr);
		}
	}
	else {
		newp = MEM_guarded_callocN(size, identity);
	}

	return newp;
}

/** \} */

/* -------------------------------------------------------------------- */
/** \name Duplication Methods
 * \{ */

void *MEM_guarded_dupallocN(void const *vptr) {
	void *newp = NULL;

	if (vptr) {
		GMemoryHead const *head = vptr;
		head--;

		do {
			if (head->align == 0) {
				newp = MEM_guarded_mallocN(head->size, head->identity);
			}
			else {
				newp = MEM_guarded_mallocN_aligned(head->size, head->align, head->identity);
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

void MEM_guarded_freeN(void *vptr) {
	GMemoryHead *head = vptr;

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

	if (sizeof(intptr_t) == 8) {
		if (((intptr_t)vptr) & 0x7) {
			fprintf(stderr, "Attempt to free illegal pointer.\n");
			abort();
			return;
		}
	}
	else {
		if (((intptr_t)vptr) & 0x3) {
			fprintf(stderr, "Attempt to free illegal pointer.\n");
			abort();
			return;
		}
	}

	head--;
	if (head->tag1 == MEMFREE && head->tag2 == MEMFREE) {
		fprintf(stderr, "Double free %p.\n", vptr);
		abort();
		return;
	}

	if ((head->tag1 == MEMTAG1) && (head->tag2 == MEMTAG2)) {
		GMemoryTail *tail = (GMemoryTail *)((char *)(head + 1) + head->size);

		if (tail->tag3 == MEMTAG3) {
			memhead_exit(head);

			if (head->align) {
				__aligned_free(((char *)head) - MEMHEAD_ALIGN_PADDING(head->align));
			}
			else {
				free(head);
			}

			return;
		}
	}

	mem_lock_thread();
	LISTBASE_FOREACH(Link *, link, membase()) {
		if (link == MEMLINK(head)) {
			fprintf(stderr, "Memory block %s has a corrupted header.\n", head->identity);
			if (head->tag1 != MEMTAG1) {
				fprintf(stderr, "invalid first-tag!\n");
			}
			if (head->tag2 != MEMTAG2) {
				fprintf(stderr, "invalid second-tag!\n");
			}
			if ((head->tag1 == MEMTAG1) && (head->tag2 == MEMTAG2)) {
				GMemoryTail *tail = (GMemoryTail *)((char *)(head + 1) + head->size);

				if (tail->tag3 != MEMTAG3) {
					fprintf(stderr, "invalid tail-tag!\n");
				}
			}
			mem_unlock_thread();
			abort();
			return;
		}
	}
	fprintf(stderr, "Memory block not in memory list.\n");
	mem_unlock_thread();
	abort();
	return;
}

/** \} */

/* -------------------------------------------------------------------- */
/** \name Query Methods
 * \{ */

size_t MEM_guarded_allocN_length(const void *vptr) {
	if (vptr) {
		const GMemoryHead *head = vptr;

		head--;
		if (head->tag1 == MEMFREE && head->tag2 == MEMFREE) {
			return 0;
		}

		if ((head->tag1 == MEMTAG1) && (head->tag2 == MEMTAG2)) {
			GMemoryTail *tail = (GMemoryTail *)((char *)(head + 1) + head->size);

			if (tail->tag3 == MEMTAG3) {
				return head->size;
			}
		}

		return 0;
	}
	return 0;
}

/** \} */

/* -------------------------------------------------------------------- */
/** \name Module Methods
 * \{ */

void MEM_guarded_print_memlist() {
	fprintf(stdout, "\n*** Memory List ***\n");
	fprintf(stdout, "{\n");
	mem_lock_thread();
	LISTBASE_FOREACH(Link *, link, membase()) {
		GMemoryHead *head = (GMemoryHead *)(((char *)link) - offsetof(GMemoryHead, prev));

		void *ptr = head + 1;
		if (head->tag1 == MEMTAG1 && head->tag2 == MEMTAG2) {
			GMemoryTail *tail = (GMemoryTail *)((char *)(head + 1) + head->size);

			if (tail->tag3 == MEMTAG3) {
				fprintf(stdout, "    { size %zu, align %zu, name '%s'", head->size, head->align, head->identity);
				if (head->size < 128) {
					fprintf(stdout, ", content '");
					for (unsigned char *p = (unsigned char *)(head + 1); p < (unsigned char *)tail; p++) {
						fprintf(stdout, "%02x", *p);
						if (isgraph(*p)) {
							fprintf(stdout, "|%c", *p);
						}
						fprintf(stdout, " ");
					}
					fprintf(stdout, "'");
				}
				fprintf(stdout, " }\n");
			}
			else {
				fprintf(stderr, "    Corrupted memory (tail) block found.\n");
			}
		}
		else {
			fprintf(stderr, "    Corrupted memory (head) block found.\n");
		}
	}
	mem_unlock_thread();
	fprintf(stdout, "}\n");
}

/** \} */
