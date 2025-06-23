#ifndef MOM_H
#define MOM_H

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

#include "list.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

// This might prove to be extremelly small, extremelly soon!
#define MOM_MAX_DLLNAME_LEN 256
#define MOM_MAX_EXPNAME_LEN 256
#define MOM_MAX_LIBNAME_LEN 256

/* -------------------------------------------------------------------- */
/** \name Datablock Definitions
 * { */

typedef struct ModuleHandle ModuleHandle;
typedef struct ModuleSection ModuleSection;
typedef struct ModuleExport ModuleExport;
typedef struct ModuleImport ModuleImport;
typedef struct ModuleRelocation ModuleRelocation;
typedef struct ModuleTLS ModuleTLS;
typedef struct ModuleException ModuleException;
typedef struct ProcessHandle ProcessHandle;
typedef struct ThreadHandle ThreadHandle;

typedef enum eMomArchitecture {
	kMomArchitectureNone,
	kMomArchitectureAmd32,
	kMomArchitectureAmd64,
} eMomArchitecture;

typedef ListBase (*fnMOM_module_open_by_file)(const char *filepath);
typedef ListBase (*fnMOM_module_open_by_name)(struct ProcessHandle *process, const char *name);
typedef struct ModuleHandle *(*fnMOM_module_open_by_image)(const void *image, size_t length);
typedef struct ModuleHandle *(*fnMOM_module_open_by_address)(struct ProcessHandle *process, const void *address, size_t length);
typedef size_t (*fnMOM_module_size)(const struct ModuleHandle *handle);
typedef const char *(*fnMOM_module_name)(const struct ModuleHandle *handle);
typedef void *(*fnMOM_module_set_address)(ModuleHandle *handle, void *address);
typedef void *(*fnMOM_module_get_address)(ModuleHandle *handle);
typedef void *(*fnMOM_module_get_base)(ModuleHandle *handle);

typedef void (*fnMOM_module_close)(struct ModuleHandle *handle);
typedef void (*fnMOM_module_close_collection)(struct ListBase *collection);

typedef eMomArchitecture (*fnMOM_module_architecture)(const struct ModuleHandle *handle);

typedef ListBase (*fnMOM_module_sections)(struct ModuleHandle *handle);
typedef ListBase (*fnMOM_module_exports)(struct ModuleHandle *handle);
typedef ListBase (*fnMOM_module_imports)(struct ModuleHandle *handle);
typedef ListBase (*fnMOM_module_imports_delayed)(struct ModuleHandle *handle);
typedef ListBase (*fnMOM_module_tls)(struct ModuleHandle *handle);
typedef ListBase (*fnMOM_module_relocations)(struct ModuleHandle *handle);

typedef const char *(*fnMOM_module_section_name)(const struct ModuleHandle *handle, const struct ModuleSection *section);
typedef void *(*fnMOM_module_section_logical)(const struct ModuleHandle *handle, const struct ModuleSection *section);
// Even if this doesn't return NULL the return address may not be owned by this process!
typedef void *(*fnMOM_module_section_physical)(const struct ModuleHandle *handle, const struct ModuleSection *section);
typedef int (*fnMOM_module_section_protection)(const struct ModuleHandle *handle, const struct ModuleSection *section);
typedef size_t (*fnMOM_module_section_size)(const struct ModuleHandle *handle, const struct ModuleSection *section);

typedef const char *(*fnMOM_module_export_name)(const struct ModuleHandle *handle, const struct ModuleExport *exported);
typedef short (*fnMOM_module_export_ordinal)(const struct ModuleHandle *handle, const struct ModuleExport *exported);
typedef bool (*fnMOM_module_export_is_ordinal)(const struct ModuleHandle *handle, const struct ModuleExport *exported);
typedef bool (*fnMOM_module_export_is_forward)(const struct ModuleHandle *handle, const struct ModuleExport *exported);
typedef bool (*fnMOM_module_export_is_fowrard_by_ordinal)(const struct ModuleHandle *handle, const struct ModuleExport *exported);
typedef const char *(*fnMOM_module_export_forward_libname)(const struct ModuleHandle *handle, const struct ModuleExport *exported);
typedef short (*fnMOM_module_export_forward_ordinal)(const struct ModuleHandle *handle, const struct ModuleExport *exported);
typedef const char *(*fnMOM_module_export_forward_name)(const struct ModuleHandle *handle, const struct ModuleExport *exported);
typedef void *(*fnMOM_module_export_logical)(const struct ModuleHandle *handle, const struct ModuleExport *exported);
// Even if this doesn't return NULL the return address may not be owned by this process!
typedef void *(*fnMOM_module_export_physical)(const struct ModuleHandle *handle, const struct ModuleExport *exported);

typedef bool (*fnMOM_module_import_is_ordinal)(const struct ModuleHandle *handle, const struct ModuleImport *imported);
typedef const char *(*fnMOM_module_import_libname)(const struct ModuleHandle *handle, const struct ModuleImport *imported);
typedef const char *(*fnMOM_module_import_expname)(const struct ModuleHandle *handle, const struct ModuleImport *imported);
typedef short (*fnMOM_module_import_expordinal)(const struct ModuleHandle *handle, const struct ModuleImport *imported);
typedef void *(*fnMOM_module_import_logical_thunk)(const struct ModuleHandle *handle, const struct ModuleImport *imported);
typedef void *(*fnMOM_module_import_logical_funk)(const struct ModuleHandle *handle, const struct ModuleImport *imported);
// Even if this doesn't return NULL the return address may not be owned by this process!
typedef void *(*fnMOM_module_import_physical_thunk)(const struct ModuleHandle *handle, const struct ModuleImport *imported);
// Even if this doesn't return NULL the return address may not be owned by this process!
typedef void *(*fnMOM_module_import_physical_funk)(const struct ModuleHandle *handle, const struct ModuleImport *imported);

typedef enum eMomRelocationType {
	kMomRelocationNone,
	kMomRelocationHigh,    // *(uint16_t **)address += HIWORD(delta);
	kMomRelocationLow,     // *(uint16_t **)address += LOWORD(delta);
	kMomRelocationHighLow, // *(uintptr_t **)address += delta;
	kMomRelocationDir64,   // *(uint64_t **)address += delta;
	kMomRelocationAbsolute,
	kMomRelocationHighAdj,
} eMomRelocationType;

typedef eMomRelocationType (*fnMOM_module_relocation_type)(const struct ModuleHandle *handle, const struct ModuleRelocation *relocation);
typedef void *(*fnMOM_module_relocation_logical)(const struct ModuleHandle *handle, const struct ModuleRelocation *relocation);
// Even if this doesn't return NULL the return address may not be owned by this process!
typedef void *(*fnMOM_module_relocation_physical)(const struct ModuleHandle *handle, const struct ModuleRelocation *relocation);

typedef enum eMomMemoryProtect {
	kMomProtectNone = 0,
	kMomProtectRead = (1 << 0),
	kMomProtectWrite = (1 << 1),
	kMomProtectExec = (1 << 2),
} eMomMemoryProtect;

typedef ListBase (*fnMOM_process_open_by_name)(const char *name);
typedef struct ProcessHandle *(*fnMOM_process_open)(int identifier);
typedef struct ProcessHandle *(*fnMOM_process_self)(void);
typedef void *(*fnMOM_process_allocate)(struct ProcessHandle *handle, const void *address, size_t size, int protect);
typedef bool (*fnMOM_process_protect)(struct ProcessHandle *handle, const void *address, size_t size, int protect);
typedef size_t (*fnMOM_process_write)(struct ProcessHandle *handle, void *address, const void *buffer, size_t size);
typedef size_t (*fnMOM_process_read)(struct ProcessHandle *handle, const void *address, void *buffer, size_t size);
typedef void (*fnMOM_process_free)(struct ProcessHandle *handle, void *address);
typedef void (*fnMOM_process_close)(struct ProcessHandle *handle);
typedef void (*fnMOM_process_close_collection)(ListBase *lb);
typedef int (*fnMOM_process_identifier)(const struct ProcessHandle *handle);

typedef ModuleHandle *(*fnMOM_process_module_find_by_name)(struct ProcessHandle *process, const char *name);
typedef ModuleHandle *(*fnMOM_process_module_push)(struct ProcessHandle *process, const ModuleHandle *handle);
typedef ModuleHandle *(*fnMOM_process_module_find)(struct ProcessHandle *process, const ModuleHandle *handle);

/** \} */

/* -------------------------------------------------------------------- */
/** \name Architecture
 * { */

size_t MOM_module_architecture_pointer_size(eMomArchitecture architecture);

/** \} */

/* -------------------------------------------------------------------- */
/** \name Modules
 * { */

// This can return a collection of modules when the name exists in the schema API
extern fnMOM_module_open_by_file MOM_module_open_by_file;
// This can return a collection of modules when the name exists in the schema API
extern fnMOM_module_open_by_name MOM_module_open_by_name;
extern fnMOM_module_open_by_image MOM_module_open_by_image;
extern fnMOM_module_open_by_address MOM_module_open_by_address;
extern fnMOM_module_size MOM_module_size;
extern fnMOM_module_name MOM_module_name;
extern fnMOM_module_set_address MOM_module_set_address;
extern fnMOM_module_get_address MOM_module_get_address;
extern fnMOM_module_get_base MOM_module_get_base;

extern fnMOM_module_close MOM_module_close;
extern fnMOM_module_close_collection MOM_module_close_collection;

extern fnMOM_module_architecture MOM_module_architecture;

extern fnMOM_module_sections MOM_module_sections;
extern fnMOM_module_exports MOM_module_exports;
extern fnMOM_module_imports MOM_module_imports;
extern fnMOM_module_imports_delayed MOM_module_imports_delayed;
extern fnMOM_module_tls MOM_module_tls;
extern fnMOM_module_relocations MOM_module_relocations;

extern fnMOM_module_section_name MOM_module_section_name;
extern fnMOM_module_section_logical MOM_module_section_logical;
// Even if this doesn't return NULL the return address may not be owned by this process!
extern fnMOM_module_section_physical MOM_module_section_physical;
extern fnMOM_module_section_protection MOM_module_section_protection;
extern fnMOM_module_section_size MOM_module_section_size;

extern fnMOM_module_import_is_ordinal MOM_module_import_is_ordinal;
extern fnMOM_module_import_libname MOM_module_import_libname;
extern fnMOM_module_import_expname MOM_module_import_expname;
extern fnMOM_module_import_expordinal MOM_module_import_expordinal;
extern fnMOM_module_import_logical_thunk MOM_module_import_logical_thunk;
extern fnMOM_module_import_logical_funk MOM_module_import_logical_funk;
// Even if this doesn't return NULL the return address may not be owned by this process!
extern fnMOM_module_import_physical_thunk MOM_module_import_physical_thunk;
// Even if this doesn't return NULL the return address may not be owned by this process!
extern fnMOM_module_import_physical_funk MOM_module_import_physical_funk;

extern fnMOM_module_export_name MOM_module_export_name;
extern fnMOM_module_export_ordinal MOM_module_export_ordinal;
extern fnMOM_module_export_is_ordinal MOM_module_export_is_ordinal;
extern fnMOM_module_export_is_forward MOM_module_export_is_forward;
extern fnMOM_module_export_is_fowrard_by_ordinal MOM_module_export_is_fowrard_by_ordinal;
extern fnMOM_module_export_forward_libname MOM_module_export_forward_libname;
extern fnMOM_module_export_forward_ordinal MOM_module_export_forward_ordinal;
extern fnMOM_module_export_forward_name MOM_module_export_forward_name;
extern fnMOM_module_export_logical MOM_module_export_logical;
// Even if this doesn't return NULL the return address may not be owned by this process!
extern fnMOM_module_export_physical MOM_module_export_physical;

ModuleExport *MOM_module_export_find_by_name(struct ModuleHandle *handle, const char *name);
ModuleExport *MOM_module_export_find_by_ordinal(struct ModuleHandle *handle, short ordinal);

extern fnMOM_module_relocation_type MOM_module_relocation_type;
extern fnMOM_module_relocation_logical MOM_module_relocation_logical;
// Even if this doesn't return NULL the return address may not be owned by this process!
extern fnMOM_module_relocation_physical MOM_module_relocation_physical;

/** \} */

/* -------------------------------------------------------------------- */
/** \name Process
 * { */

// This can return a collection of processes when there are mutiple application with this name
extern fnMOM_process_open_by_name MOM_process_open_by_name;
extern fnMOM_process_open MOM_process_open;
extern fnMOM_process_self MOM_process_self;
extern fnMOM_process_allocate MOM_process_allocate;
extern fnMOM_process_protect MOM_process_protect;
extern fnMOM_process_write MOM_process_write;
extern fnMOM_process_read MOM_process_read;
extern fnMOM_process_free MOM_process_free;
extern fnMOM_process_close MOM_process_close;
extern fnMOM_process_close_collection MOM_process_close_collection;
extern fnMOM_process_identifier MOM_process_identifier;

// This is the list of all known loaded modules inside a process!
extern fnMOM_process_module_push MOM_process_module_push;
extern fnMOM_process_module_find MOM_process_module_find;
extern fnMOM_process_module_find_by_name MOM_process_module_find_by_name;

/** \} */

#ifdef __cplusplus
}
#endif

#if defined(WIN32) && defined(UNIX)
/* Want to comment the following line out? Be my guest I hope you know what the fuck you are doing... */
#	error "I understand that some people, and I am not pointing any fingers, were raised by two moms but this isn't LGBTQ bud, drop the bullshit!"
#endif

#if defined(WIN32)
// #	include "windows/winmom.h"
#endif

#if defined(UNIX)
// #	include "unix/unixmom.h"
#endif

#endif
