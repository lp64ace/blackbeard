#ifndef CONFIG_H
#define CONFIG_H

#define BOB_DEBUG_MESSAGES 0

#if BOB_DEBUG_MESSAGES
#	include <stdio.h>
#	define BOB_DEBUG_PRINT(...) fprintf(__VA_ARGS__)
#else
#	define BOB_DEBUG_PRINT(...) ((void)0)
#endif


#include <math.h>
#include <stdarg.h>
#include <string.h>

#ifndef BOB_ALLOC
#	include <malloc.h>
#	define BOB_ALLOC(size) malloc(size)
#	define BOB_FREE(ptr) free(ptr)
#endif

/* -------------------------------------------------------------------- */
/** \name Pointer Macros
 * \{ */

#define POINTER_OFFSET(ptr, offset) (void *)(((char *)ptr) + (offset))

#define POINTER_FROM_INT(i) ((void *)(intptr_t)(i))
#define POINTER_AS_INT(i) ((void)0, ((int)(intptr_t)(i)))

#define POINTER_FROM_UINT(i) ((void *)(uintptr_t)(i))
#define POINTER_AS_UINT(i) ((void)0, ((unsigned int)(uintptr_t)(i)))

/** \} */

/* -------------------------------------------------------------------- */
/** \name String Macros
 * \{ */

/* Macro to convert a value to string in the preprocessor:
 * - `STRINGIFY_ARG`: gives the argument as a string
 * - `STRINGIFY_APPEND`: appends any argument 'b' onto the string argument 'a',
 *   used by `STRINGIFY` because some preprocessors warn about zero arguments.
 * - `STRINGIFY`: gives the argument's value as a string. */

#define STRINGIFY_ARG(x) "" #x
#define STRINGIFY_APPEND(a, b) "" a #b
#define STRINGIFY(x) STRINGIFY_APPEND("", x)

#define STRINGIFY_TOKEN(Define) #Define
#define STRINGIFY_DEFINE(Define) STRINGIFY_TOKEN(Define)

/* generic strcmp macros */
#if defined(_MSC_VER)
#	define strcasecmp _stricmp
#	define strncasecmp _strnicmp
#endif

#define STREQ(a, b) (strcmp(a, b) == 0)
#define STRCASEEQ(a, b) (strcasecmp(a, b) == 0)
#define STREQLEN(a, b, n) (strncmp(a, b, n) == 0)
#define STRCASEEQLEN(a, b, n) (strncasecmp(a, b, n) == 0)

#define STRPREFIX(a, b) (strncmp((a), (b), strlen(b)) == 0)

/** \} */

/* -------------------------------------------------------------------- */
/** \name Inline Attributes
 * \{ */

#if defined(_MSC_VER)
#	define BOB_INLINE __forceinline
#	define BOB_STATIC static
#else
#	define BOB_INLINE inline __attribute__((always_inline)) __attribute__((__unused__))
#	define BOB_STATIC static
#endif

#if defined(_MSC_VER)
#	define BOB_NOINLINE __declspec(noinline)
#elif defined(__GNUC__)
#	define BOB_NOINLINE __attribute__((noinline))
#else
#	define BOB_NOINLINE
#endif

/** /} */

#endif
