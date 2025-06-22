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

#include "defines.h"
#include "list.h"
#include "mom.h"

#ifdef __cplusplus
extern "C" {
#endif

/* -------------------------------------------------------------------- */
/** \name Datablock Definitions
 * { */

typedef struct ProcessHandle {
	ListBase modules;

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

	ProcessHandle *process;
	uintptr_t disk;
	uintptr_t base;
	uintptr_t real;
	char dllname[MOM_MAX_DLLNAME_LEN];
	
	ListBase sections;
	ListBase exports;
	ListBase imports;
	ListBase delayed_imports;
	ListBase tls;
	ListBase exceptions;
	ListBase relocations;
	
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
