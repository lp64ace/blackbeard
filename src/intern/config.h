#ifndef __BOB_CONFIG_H__
#define __BOB_CONFIG_H__

#include <string.h>

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
#define strcasecmp _stricmp
#define strncasecmp _strnicmp
#endif

#define STREQ(a, b) (strcmp(a, b) == 0)
#define STRCASEEQ(a, b) (strcasecmp(a, b) == 0)
#define STREQLEN(a, b, n) (strncmp(a, b, n) == 0)
#define STRCASEEQLEN(a, b, n) (strncasecmp(a, b, n) == 0)

#define STRPREFIX(a, b) (strncmp((a), (b), strlen(b)) == 0)

/** \} */

#endif
