#ifndef MOM_INTERNAL_H
#define MOM_INTERNAL_H

/*
 * MIT License
 *
 * Copyright (c) 2024 dmpokisk
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include "mom.h"

#ifdef __cplusplus
extern "C" {
#endif

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

/* -------------------------------------------------------------------- */
/** \name List Macros
 * \{ */

/**
 * A version of #LIST_FOREACH_MUTABLE that supports removing the item we're looping over.
 */
#define LIST_FOREACH_MUTABLE(type, var, first) for (type var = (type)(first), *var##_iter_next; ((var != NULL) ? ((void)(var##_iter_next = (type)((var)->next)), 1) : 0); var = var##_iter_next)

/** \} */

/* -------------------------------------------------------------------- */
/** \name Datablock Definitions
 * { */

typedef struct ProcessHandle {
	struct ModuleHandle *modules;

	// Native handle, this should probably be added into a private section?
	uintptr_t native;
} ProcessHandle;

/*
 * Module sections usualy consist of a header and some raw data.
 * The data is just plain bullshit located in a blob within the file.
 * That data after relocations and imports are applied are mapped to memory.
 *
 * \member src The pointer within the image loaded from disk.
 * \member dst The pointer within the image loaded from memory.
 * \note If the module is not mapped to memory then the #dst points to the 
 * virtual address of the section.
 *
 * I quote MSDN docs;
 * Each module has a desired location in memory it want to be mapped into.
 * Though this is rarely the case, all addresses are relative to this virtual address.
 */

typedef struct ModuleSection {
	struct ModuleSection *prev, *next;
	uintptr_t src;
	uintptr_t dst;

	/**
	 * The following can be used however the native implementation deems appropriate!
	 * These are currently used by the Windows implementation!
	 * 
	 * \note In case the naming doesn't fit the purpose of both implementations, 
	 * the name should be changed to something more generic like 'payload' or 'private'
	 */
	char header[];
} ModuleSection;

typedef struct ModuleExport {
	struct ModuleExport *prev, *next;
	uintptr_t ordinal;
	uintptr_t fwdordinal;
	char expname[MOM_MAX_EXPNAME_LEN];
	char fwdname[MOM_MAX_EXPNAME_LEN];
	char libname[MOM_MAX_LIBNAME_LEN];
	uintptr_t src;
	uintptr_t dst;
} ModuleExport;

typedef struct ModuleImport {
	struct ModuleImport *prev, *next;
	uintptr_t ordinal;
	char expname[MOM_MAX_EXPNAME_LEN];
	char libname[MOM_MAX_LIBNAME_LEN];
	uintptr_t from;
	uintptr_t to;
} ModuleImport;

typedef struct ModuleTLS {
	struct ModuleTLS *prev, *next;

	uintptr_t src;
	uintptr_t dst;
} ModuleTLS;

typedef struct ModuleException {
	struct ModuleException *prev, *next;

	uintptr_t src;
	uintptr_t dst;
} ModuleException;

typedef struct ModuleRelocation {
	struct ModuleRelocation *prev, *next;

	uintptr_t src;
	uintptr_t dst;
	eMomRelocationType type;
} ModuleRelocation;

typedef struct ModuleHandle {
	struct ModuleHandle *prev, *next;
	uintptr_t disk;
	uintptr_t base;
	uintptr_t real;
	char dllname[MOM_MAX_DLLNAME_LEN];
	
	ProcessHandle *process;
	ModuleSection *sections;
	ModuleExport *exports;
	ModuleImport *imports;
	ModuleImport *delayed_imports;
	ModuleTLS *tls;
	ModuleException *exceptions;
	ModuleRelocation *relocations;
	
	/**
	 * The following can be used however the native implementation deems appropriate!
	 * These are currently used by the Windows implementation!
	 *
	 * \note In case the naming doesn't fit the purpose of both implementations,
	 * the name should be changed to something more generic like 'payload' or 'private'
	 */
	char image[];
} ModuleHandle;

typedef bool (*fnMOM_module_header_is_valid)(const struct ModuleHandle *handle);

/** \} */

/* -------------------------------------------------------------------- */
/** \name Architecture Internal
 * { */

size_t MOM_module_architecture_pointer_size(eMomArchitecture architecture);

/** \} */

/* -------------------------------------------------------------------- */
/** \name Modules Internal
 * { */


extern fnMOM_module_header_is_valid MOM_module_header_is_valid;

/** \} */

#ifdef __cplusplus
}
#endif

#endif
