#ifndef WINMOM_H
#define WINMOM_H

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

#include "mom.h" // This will always trigger the include lock, here for intellisense!

#include <fcntl.h>
#include <io.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>

/* I would strongly argue that Windows are never lean nor mean they are straight up SHIT! */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h>
#include <tchar.h>

#undef max
#undef min

#ifdef __cplusplus
extern "C" {
#endif

/* -------------------------------------------------------------------- */
/** \name Datablock Definitions
 * { */

typedef struct SchemaEntry {
	struct SchemaEntry *perv, *next;

	/**
	 * The logical name is not of interest we only care about the physical value!
	 */
	char physical[MOM_MAX_DLLNAME_LEN];
} SchemaEntry;

typedef NTSTATUS(NTAPI *fnNtQueryInformationProcess)(IN HANDLE ProcessHandle, IN PROCESSINFOCLASS ProcessInformationClass, OUT PVOID ProcessInformation, IN ULONG ProcessInformationLength, OUT PULONG ReturnLength OPTIONAL);
typedef NTSTATUS(NTAPI *fnNtCreateThreadEx)(OUT PHANDLE ThreadHandle, IN ACCESS_MASK DesiredAccess, IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL, IN HANDLE ProcessHandle, IN LPVOID Routine, IN PVOID Argument OPTIONAL, IN ULONG CreateFlags, IN SIZE_T ZeroBits, IN SIZE_T StackSize, IN SIZE_T MaximumStackSize, IN LPVOID AttributeList OPTIONAL);

/** \} */

/* -------------------------------------------------------------------- */
/** \name Platform Internals
 * { */

void *winmom_resolve_proc(const char *dllname, const char *procname);

/** \} */

/* -------------------------------------------------------------------- */
/** \name Module Platform Dependent
 * { */

HMODULE winmom_module_handle(struct ModuleHandle *handle);

bool winmom_module_loaded_match_name(const char *asbolute, const char *name);

/** \} */

/* -------------------------------------------------------------------- */
/** \name Process Platform Dependent
 * { */

ListBase winmom_process_resolve_schema(const char *logical);

HANDLE winmom_process_handle(struct ProcessHandle *handle);
LPVOID winmom_process_peb(struct ProcessHandle *handle, PEB *peb);
LPVOID winmom_current_peb(PEB *peb);

/** \} */

#ifdef __cplusplus
}
#endif

#endif
