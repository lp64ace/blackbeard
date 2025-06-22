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
typedef struct ModuleTLS ModuleTLS;
typedef struct ProcessHandle ProcessHandle;

typedef enum eMomArchitecture {
	kMomArchitectureNone,
	kMomArchitectureAmd32,
	kMomArchitectureAmd64,
} eMomArchitecture;

typedef enum eMomRelocationType {
	kMomRelocationNone,
	kMomRelocationHigh,    // *(uint16_t **)address += HIWORD(delta);
	kMomRelocationLow,     // *(uint16_t **)address += LOWORD(delta);
	kMomRelocationHighLow, // *(uintptr_t **)address += delta;
	kMomRelocationDir64,   // *(uint64_t **)address += delta;
	kMomRelocationAbsolute,
	kMomRelocationHighAdj,
} eMomRelocationType;

typedef struct ModuleHandle *(*fnMOM_module_open_by_file)(const char *filepath);
typedef struct ModuleHandle *(*fnMOM_module_open_by_name)(struct ProcessHandle *process, const char *name);
typedef struct ModuleHandle *(*fnMOM_module_open_by_image)(const void *image, size_t length);
typedef struct ModuleHandle *(*fnMOM_module_open_by_address)(struct ProcessHandle *process, const void *address, size_t length);
typedef struct ModuleHandle *(*fnMOM_module_prev)(struct ModuleHandle *handle);
typedef struct ModuleHandle *(*fnMOM_module_next)(struct ModuleHandle *handle);
typedef const char *(*fnMOM_module_name)(struct ModuleHandle *handle);
typedef void (*fnMOM_module_close)(struct ModuleHandle *handle);
typedef void *(*fnMOM_module_address)(struct ModuleHandle *handle);
typedef size_t (*fnMOM_module_image_size)(const struct ModuleHandle *handle);
typedef size_t (*fnMOM_module_memory_size)(const struct ModuleHandle *handle);
typedef eMomArchitecture (*fnMOM_module_architecture)(const struct ModuleHandle *handle);
typedef struct ModuleSection *(*fnMOM_module_section_begin)(struct ModuleHandle *handle);
typedef struct ModuleSection *(*fnMOM_module_section_end)(struct ModuleHandle *handle);
typedef struct ModuleSection *(*fnMOM_module_section_next)(struct ModuleHandle *handle, struct ModuleSection *itr);
typedef const char *(*fnMOM_module_section_name)(const struct ModuleHandle *handle, const struct ModuleSection *section);
typedef int (*fnMOM_module_section_protect)(const struct ModuleHandle *handle, const struct ModuleSection *section);
typedef void *(*fnMOM_module_section_disk)(const struct ModuleHandle *handle, struct ModuleSection *section);
// Even if this doesn't return NULL there is a good chance that this pointer is not owned by this process!
typedef void *(*fnMOM_module_section_memory)(const struct ModuleHandle *handle, struct ModuleSection *section);
typedef size_t (*fnMOM_module_section_size)(const struct ModuleHandle *handle, const struct ModuleSection *section);
typedef struct ModuleExport *(*fnMOM_module_export_begin)(struct ModuleHandle *handle);
typedef struct ModuleExport *(*fnMOM_module_export_end)(struct ModuleHandle *handle);
typedef struct ModuleExport *(*fnMOM_module_export_next)(struct ModuleHandle *handle, struct ModuleExport *itr);
typedef struct ModuleExport *(*fnMOM_module_export_find_by_name)(struct ModuleHandle *handle, const char *name);
typedef struct ModuleExport *(*fnMOM_module_export_find_by_ordinal)(struct ModuleHandle *handle, int ordinal);
typedef const void *(*fnMOM_module_export_disk)(struct ModuleHandle *handle, const struct ModuleExport *exported);
// Even if this doesn't return NULL there is a good chance that this pointer is not owned by this process!
typedef const void *(*fnMOM_module_export_memory)(struct ModuleHandle *handle, const struct ModuleExport *exported);
typedef int (*fnMOM_module_export_ordinal)(const struct ModuleHandle *handle, const struct ModuleExport *exported);
typedef int (*fnMOM_module_export_forward_ordinal)(const struct ModuleHandle *handle, const struct ModuleExport *exported);
typedef const char *(*fnMOM_module_export_forward_name)(const struct ModuleHandle *handle, const struct ModuleExport *exported);
typedef const char *(*fnMOM_module_export_name)(const struct ModuleHandle *handle, const struct ModuleExport *exported);
typedef const char *(*fnMOM_module_export_lib)(const struct ModuleHandle *handle, const struct ModuleExport *exported);
typedef struct ModuleImport *(*fnMOM_module_import_begin)(struct ModuleHandle *handle);
typedef struct ModuleImport *(*fnMOM_module_import_end)(struct ModuleHandle *handle);
typedef struct ModuleImport *(*fnMOM_module_import_next)(struct ModuleHandle *handle, struct ModuleImport *itr);
typedef void *(*fnMOM_module_import_from_disk)(struct ModuleHandle *handle, struct ModuleImport *imported);
typedef void *(*fnMOM_module_import_to_disk)(struct ModuleHandle *handle, struct ModuleImport *imported);
// Even if this doesn't return NULL there is a good chance that this pointer is not owned by this process!
typedef void *(*fnMOM_module_import_from_memory)(struct ModuleHandle *handle, struct ModuleImport *imported);
typedef void *(*fnMOM_module_import_to_memory)(struct ModuleHandle *handle, struct ModuleImport *imported);
typedef int (*fnMOM_module_import_ordinal)(const struct ModuleHandle *handle, const struct ModuleImport *imported);
typedef const char *(*fnMOM_module_import_name)(const struct ModuleHandle *handle, const struct ModuleImport *imported);
typedef const char *(*fnMOM_module_import_lib)(const struct ModuleHandle *handle, const struct ModuleImport *imported);
typedef struct ModuleImport *(*fnMOM_module_import_delayed_begin)(struct ModuleHandle *handle);
typedef struct ModuleImport *(*fnMOM_module_import_delayed_end)(struct ModuleHandle *handle);
typedef struct ModuleImport *(*fnMOM_module_import_delayed_next)(struct ModuleHandle *handle, struct ModuleImport *itr);
typedef struct ModuleTLS *(*fnMOM_module_tls_begin)(struct ModuleHandle *handle);
typedef struct ModuleTLS *(*fnMOM_module_tls_end)(struct ModuleHandle *handle);
typedef struct ModuleTLS *(*fnMOM_module_tls_next)(struct ModuleHandle *handle, struct ModuleTLS *itr);
typedef void *(*fnMOM_module_tls_disk)(const struct ModuleHandle *handle, struct ModuleTLS *tls);
// Even if this doesn't return NULL there is a good chance that this pointer is not owned by this process!
typedef void *(*fnMOM_module_tls_memory)(const struct ModuleHandle *handle, struct ModuleTLS *tls);
typedef struct ModuleRelocation *(*fnMOM_module_relocation_begin)(struct ModuleHandle *handle);
typedef struct ModuleRelocation *(*fnMOM_module_relocation_end)(struct ModuleHandle *handle);
typedef struct ModuleRelocation *(*fnMOM_module_relocation_next)(struct ModuleHandle *handle, struct ModuleRelocation *itr);
typedef void *(*fnMOM_module_relocation_disk)(const struct ModuleHandle *handle, struct ModuleRelocation *relocation);
// Even if this doesn't return NULL there is a good chance that this pointer is not owned by this process!
typedef void *(*fnMOM_module_relocation_memory)(const struct ModuleHandle *handle, struct ModuleRelocation *relocation);
typedef eMomRelocationType (*fnMOM_module_relocation_type)(const struct ModuleHandle *handle, const struct ModuleRelocation *relocation);

typedef enum eMomMemoryProtect {
	kMomProtectNone = 0,
	kMomProtectRead = (1 << 0),
	kMomProtectWrite = (1 << 1),
	kMomProtectExec = (1 << 2),
} eMomMemoryProtect;

typedef struct ProcessHandle *(*fnMOM_process_open)(int identifier);
typedef struct ProcessHandle *(*fnMOM_process_self)(void);
typedef void *(*fnMOM_process_allocate)(struct ProcessHandle *handle, const void *address, size_t size, int protect);
typedef bool (*fnMOM_process_protect)(struct ProcessHandle *handle, const void *address, size_t size, int protect);
typedef size_t (*fnMOM_process_write)(struct ProcessHandle *handle, void *address, const void *buffer, size_t size);
typedef size_t (*fnMOM_process_read)(struct ProcessHandle *handle, const void *address, void *buffer, size_t size);
typedef void (*fnMOM_process_free)(struct ProcessHandle *handle, void *address);
typedef void (*fnMOM_process_close)(struct ProcessHandle *handle);
typedef int (*fnMOM_process_identifier)(const struct ProcessHandle *handle);

// This is the list of all known loaded modules inside a process!
typedef ModuleHandle *(*fnMOM_process_module_push)(struct ProcessHandle *process, const ModuleHandle *handle);
typedef ModuleHandle *(*fnMOM_process_module_find)(struct ProcessHandle *process, const ModuleHandle *handle);
typedef ModuleHandle *(*fnMOM_process_module_begin)(struct ProcessHandle *process);
typedef ModuleHandle *(*fnMOM_process_module_end)(struct ProcessHandle *process);
typedef ModuleHandle *(*fnMOM_process_module_next)(struct ProcessHandle *process, struct ModuleHandle *itr);

/** \} */

/* -------------------------------------------------------------------- */
/** \name Modules
 * { */

extern fnMOM_module_open_by_file MOM_module_open_by_file;
extern fnMOM_module_open_by_name MOM_module_open_by_name;
extern fnMOM_module_open_by_image MOM_module_open_by_image;
extern fnMOM_module_open_by_address MOM_module_open_by_address;
extern fnMOM_module_prev MOM_module_prev;
extern fnMOM_module_next MOM_module_next;
extern fnMOM_module_name MOM_module_name;
extern fnMOM_module_close MOM_module_close;
extern fnMOM_module_address MOM_module_address;
extern fnMOM_module_image_size MOM_module_image_size;
extern fnMOM_module_memory_size MOM_module_memory_size;
extern fnMOM_module_architecture MOM_module_architecture;
extern fnMOM_module_section_begin MOM_module_section_begin;
extern fnMOM_module_section_end MOM_module_section_end;
extern fnMOM_module_section_next MOM_module_section_next;
extern fnMOM_module_section_name MOM_module_section_name;
extern fnMOM_module_section_protect MOM_module_section_protect;
extern fnMOM_module_section_disk MOM_module_section_disk;
extern fnMOM_module_section_memory MOM_module_section_memory;
extern fnMOM_module_section_size MOM_module_section_size;
extern fnMOM_module_export_begin MOM_module_export_begin;
extern fnMOM_module_export_end MOM_module_export_end;
extern fnMOM_module_export_next MOM_module_export_next;
extern fnMOM_module_export_find_by_name MOM_module_export_find_by_name;
extern fnMOM_module_export_find_by_ordinal MOM_module_export_find_by_ordinal;
extern fnMOM_module_export_disk MOM_module_export_disk;
extern fnMOM_module_export_memory MOM_module_export_memory;
extern fnMOM_module_export_ordinal MOM_module_export_ordinal;
extern fnMOM_module_export_forward_ordinal MOM_module_export_forward_ordinal;
extern fnMOM_module_export_forward_name MOM_module_export_forward_name;
extern fnMOM_module_export_lib MOM_module_export_lib;
extern fnMOM_module_export_name MOM_module_export_name;
extern fnMOM_module_import_begin MOM_module_import_begin;
extern fnMOM_module_import_end MOM_module_import_end;
extern fnMOM_module_import_next MOM_module_import_next;
extern fnMOM_module_import_from_disk MOM_module_import_from_disk;
extern fnMOM_module_import_to_disk MOM_module_import_to_disk;
extern fnMOM_module_import_from_memory MOM_module_import_from_memory;
extern fnMOM_module_import_to_memory MOM_module_import_to_memory;
extern fnMOM_module_import_ordinal MOM_module_import_ordinal;
extern fnMOM_module_import_name MOM_module_import_name;
extern fnMOM_module_import_lib MOM_module_import_lib;
extern fnMOM_module_import_delayed_begin MOM_module_import_delayed_begin;
extern fnMOM_module_import_delayed_end MOM_module_import_delayed_end;
extern fnMOM_module_import_delayed_next MOM_module_import_delayed_next;
extern fnMOM_module_tls_begin MOM_module_tls_begin;
extern fnMOM_module_tls_end MOM_module_tls_end;
extern fnMOM_module_tls_next MOM_module_tls_next;
extern fnMOM_module_tls_disk MOM_module_tls_disk;
extern fnMOM_module_tls_memory MOM_module_tls_memory;
extern fnMOM_module_relocation_begin MOM_module_relocation_begin;
extern fnMOM_module_relocation_end MOM_module_relocation_end;
extern fnMOM_module_relocation_next MOM_module_relocation_next;
extern fnMOM_module_relocation_disk MOM_module_relocation_disk;
extern fnMOM_module_relocation_memory MOM_module_relocation_memory;
extern fnMOM_module_relocation_type MOM_module_relocation_type;

/** \} */

/* -------------------------------------------------------------------- */
/** \name Process
 * { */

extern fnMOM_process_open MOM_process_open;
extern fnMOM_process_self MOM_process_self;
extern fnMOM_process_allocate MOM_process_allocate;
extern fnMOM_process_protect MOM_process_protect;
extern fnMOM_process_write MOM_process_write;
extern fnMOM_process_read MOM_process_read;
extern fnMOM_process_free MOM_process_free;
extern fnMOM_process_close MOM_process_close;
extern fnMOM_process_identifier MOM_process_identifier;

extern fnMOM_process_module_push MOM_process_module_push;
extern fnMOM_process_module_find MOM_process_module_find;
extern fnMOM_process_module_begin MOM_process_module_begin;
extern fnMOM_process_module_end MOM_process_module_end;
extern fnMOM_process_module_next MOM_process_module_next;

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
