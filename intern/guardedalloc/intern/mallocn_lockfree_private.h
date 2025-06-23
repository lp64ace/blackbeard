#ifndef MACLLOCN_LOCKFREE_PRIVATE_H
#define MACLLOCN_LOCKFREE_PRIVATE_H

#include <stdint.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

/* -------------------------------------------------------------------- */
/** \name Structures
 * \{ */

typedef struct LAlignedMemoryHead {
	/**
	 * The allignment of this memory block in case this was allocated by an
	 * alligned memory allocator.
	 */
	size_t align;
	/**
	 * The size of this memory block in bytes.
	 */
	size_t size;
} LAlignedMemoryHead;

typedef struct LMemoryHead {
	/**
	 * The size of this memory block in bytes.
	 *
	 * \note Odd size is not allowed, the last bit is used as a flag when the
	 * memory is aligned.
	 */
	size_t size;
} LMemoryHead;

/** \} */

/* -------------------------------------------------------------------- */
/** \name Query Methods
 * \{ */

/** Returns the size of the allocated memory block. */
size_t MEM_lockfree_allocN_length(const void *vptr);

/** \} */

/* -------------------------------------------------------------------- */
/** \name Allocation Methods
 * \{ */

/**
 * Allocates a named memory block.
 *
 * \param[in] size The size, in bytes, of the memory block we want to allocate.
 * \param[in] identity A static string identifying the memory block.
 *
 * \return If the function succeeds, the return value is a pointer to the
 * allocated memory block.
 */
void *MEM_lockfree_mallocN(size_t size, char const *identity);
/**
 * Allocates an alligned named memory block.
 *
 * \param[in] size The size, in bytes, of the memory block we want to allocate.
 * \param[in] align The alignment, in bytes, of the memory block we want to
 * allocate. \param[in] identity A static string identifying the memory block.
 *
 * \return If the function succeeds, the return value is a pointer to the
 * allocated memory block.
 */
void *MEM_lockfree_mallocN_aligned(size_t size, size_t align, char const *identity);

/**
 * Allocates a named memory block. The allocated memory is initialized to zero.
 *
 * \param[in] size The size, in bytes, of the memory block we want to allocate.
 * \param[in] identity A static string identifying the memory block.
 *
 * \return If the function succeeds, the return value is a pointer to the
 * allocated memory block.
 */
void *MEM_lockfree_callocN(size_t size, char const *identity);
/**
 * Allocates an alligned named memory block. The allocated memory is initialized
 * to zero.
 *
 * \param[in] size The size, in bytes, of the memory block we want to allocate.
 * \param[in] align The alignment, in bytes, of the memory block we want to
 * allocate. \param[in] identity A static string identifying the memory block.
 *
 * \return If the function succeeds, the return value is a pointer to the
 * allocated memory block.
 */
void *MEM_lockfree_callocN_aligned(size_t size, size_t align, char const *identity);

/** \} */

/* -------------------------------------------------------------------- */
/** \name Reallocation Methods
 * \{ */

/**
 * Reallocate a memory block.
 *
 * \param[in] vptr Pointer to the previously allocated memory block.
 * \param[in] size The new size, in bytes.
 * \param[in] identity A static string identifying the memory block.
 *
 * \note The identity of the block is not changed if the memory block was
 * already named. \note If the function fails the old pointer remains valid.
 *
 * \return If the function succeeds, the return value is a pointer to the
 * reallocated memory block.
 */
void *MEM_lockfree_reallocN_id(void *vptr, size_t size, char const *identity);
/**
 * Reallocate a memory block. Any extra allocated memory is initialized to zero.
 *
 * \param[in] vptr Pointer to the previously allocated memory block.
 * \param[in] size The new size, in bytes.
 * \param[in] identity A static string identifying the memory block.
 *
 * \note The identity of the block is not changed if the memory block was
 * already named. \note If the function fails the old pointer remains valid.
 *
 * \return If the function succeeds, the return value is a pointer to the
 * reallocated memory block.
 */
void *MEM_lockfree_recallocN_id(void *vptr, size_t size, char const *identity);

#define MEM_lockfree_reallocN(vptr, size) MEM_lockfree_reallocN_id(vptr, size, __func__)
#define MEM_lockfree_recallocN(vptr, size) MEM_lockfree_recallocN_id(vptr, size, __func__)

/** \} */

/* -------------------------------------------------------------------- */
/** \name Duplication Methods
 * \{ */

/**
 * Duplicates a memory block.
 *
 * \param[in] vptr Pointer to the previously allocated memory block.
 *
 * \note This function returns NULL only if vptr is NULL.
 *
 * \return If the function succeeds, the return value is a pointer to the
 * duplicated memory block.
 */
void *MEM_lockfree_dupallocN(void const *vptr);

/** \} */

/* -------------------------------------------------------------------- */
/** \name Deallocation Methods
 * \{ */

/**
 * Deallocates or frees a memory block.
 *
 * \param[in] vptr Previously allocated memory block to be freed.
 */
void MEM_lockfree_freeN(void *vptr);

/** \} */

/* -------------------------------------------------------------------- */
/** \name Module Methods
 * \{ */

/**
 * Does nothing, since we do not keep a list of all our memory blocks.
 */
void MEM_lockfree_print_memlist();

/** \} */

#ifdef __cplusplus
}
#endif

#endif	// MACLLOCN_LOCKFREE_PRIVATE_H
