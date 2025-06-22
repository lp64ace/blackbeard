#ifndef __DEFINES_H__
#define __DEFINES_H__

/* -------------------------------------------------------------------- */
/** \name Array Macros
 * \{ */

#define ARRAY_HAS_ITEM(arr_item, arr_start, arr_len) ((size_t)((ptrdiff_t)(arr_item) - (ptrdiff_t)(arr_start)) < (size_t)(arr_len))

/** Return the number of elements in a static array of elements. */
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof(*(arr)))

/** \} */

/* -------------------------------------------------------------------- */
/** \name Pointer Macros
 * \{ */

#define POINTER_OFFSET(ptr, offset) (void *)(((char *)ptr) + (offset))

#define POINTER_FROM_INT(i) ((void *)(intptr_t)(i))
#define POINTER_AS_INT(i) ((void)0, ((int)(intptr_t)(i)))

#define POINTER_FROM_UINT(i) ((void *)(uintptr_t)(i))
#define POINTER_AS_UINT(i) ((void)0, ((unsigned int)(uintptr_t)(i)))

/** \} */

#endif
