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

#include "mom_internal.h"
#include "mom.h"

/* -------------------------------------------------------------------- */
/** \name Architecture
 * { */

/* clang-format off */

size_t MOM_module_architecture_pointer_size(eMomArchitecture architecture) {
	switch (architecture) {
		case kMomArchitectureAmd32: return sizeof(int32_t);
		case kMomArchitectureAmd64: return sizeof(int64_t);
	}
	return 0;
}

/* clang-format on */

/** \} */

/* -------------------------------------------------------------------- */
/** \name Module
 * { */

ModuleHandle *mom_module_prev(ModuleHandle *handle) {
	return handle->next;
}

ModuleHandle *mom_module_next(ModuleHandle *handle) {
	return handle->next;
}

const char *mom_module_name(ModuleHandle *handle) {
	return (handle->dllname[0]) ? handle->dllname : NULL;
}

ModuleSection *mom_module_section_end(ModuleHandle *handle) {
	return NULL;
}

ModuleSection *mom_module_section_next(ModuleHandle *handle, ModuleSection *section) {
	return (section) ? section->next : section;
}

ModuleExport *mom_module_export_end(ModuleHandle *handle) {
	return NULL;
}

ModuleExport *mom_module_export_next(ModuleHandle *handle, ModuleExport *export) {
	return (export) ? export->next : export;
}

int mom_module_export_ordinal(const ModuleHandle *handle, const ModuleExport *export) {
	return export->ordinal;
}

int mom_module_export_forward_ordinal(const ModuleHandle *handle, const ModuleExport *export) {
	return export->fwdordinal;
}

const char *mom_module_export_forward_name(const ModuleHandle *handle, const ModuleExport *export) {
	return (export->fwdname[0]) ? export->fwdname : NULL;
}

const char *mom_module_export_name(const ModuleHandle *handle, const ModuleExport *export) {
	return (export->expname[0]) ? export->expname : NULL;
}

const char *mom_module_export_lib(const ModuleHandle *handle, const ModuleExport *export) {
	return (export->libname[0]) ? export->libname : NULL;
}

ModuleImport *mom_module_import_end(ModuleHandle *handle) {
	return NULL;
}

ModuleImport *mom_module_import_next(ModuleHandle *handle, ModuleImport *import) {
	return (import) ? import->next : import;
}

int mom_module_import_ordinal(const ModuleHandle *handle, const ModuleImport *import) {
	return import->ordinal;
}

const char *mom_module_import_name(const ModuleHandle *handle, const ModuleImport *import) {
	return (import->expname[0]) ? import->expname : NULL;
}

const char *mom_module_import_lib(const ModuleHandle *handle, const ModuleImport *import) {
	return (import->libname[0]) ? import->libname : NULL;
}

ModuleImport *mom_module_import_delayed_end(ModuleHandle *handle) {
	return NULL;
}

ModuleImport *mom_module_import_delayed_next(ModuleHandle *handle, ModuleImport *import) {
	return (import) ? import->next : import;
}

ModuleTLS *mom_module_tls_end(ModuleHandle *handle) {
	return NULL;
}

ModuleTLS *mom_module_tls_next(ModuleHandle *handle, ModuleTLS *tls) {
	return (tls) ? tls->next : tls;
}

ModuleRelocation *mom_module_relocation_end(ModuleHandle *handle) {
	return NULL;
}

ModuleRelocation *mom_module_relocation_next(ModuleHandle *handle, ModuleRelocation *itr) {
	return (itr) ? itr->next : itr;
}

ModuleHandle *winmom_process_module_begin(ProcessHandle *handle) {
	return handle->modules;
}

ModuleHandle *winmom_process_module_end(ProcessHandle *handle) {
	return NULL;
}

ModuleHandle *winmom_process_module_next(ProcessHandle *handle, ModuleHandle *itr) {
	return (itr) ? itr->next : itr;
}

/** \} */

/* -------------------------------------------------------------------- */
/** \name Exports
 * { */

fnMOM_module_next MOM_module_prev = mom_module_prev;
fnMOM_module_next MOM_module_next = mom_module_next;
fnMOM_module_name MOM_module_name = mom_module_name;
fnMOM_module_section_end MOM_module_section_end = mom_module_section_end;
fnMOM_module_section_next MOM_module_section_next = mom_module_section_next;
fnMOM_module_export_end MOM_module_export_end = mom_module_export_end;
fnMOM_module_export_next MOM_module_export_next = mom_module_export_next;
fnMOM_module_export_ordinal MOM_module_export_ordinal = mom_module_export_ordinal;
fnMOM_module_export_forward_ordinal MOM_module_export_forward_ordinal = mom_module_export_forward_ordinal;
fnMOM_module_export_forward_name MOM_module_export_forward_name = mom_module_export_forward_name;
fnMOM_module_export_name MOM_module_export_name = mom_module_export_name;
fnMOM_module_export_lib MOM_module_export_lib = mom_module_export_lib;
fnMOM_module_import_end MOM_module_import_end = mom_module_import_end;
fnMOM_module_import_next MOM_module_import_next = mom_module_import_next;
fnMOM_module_import_ordinal MOM_module_import_ordinal = mom_module_import_ordinal;
fnMOM_module_import_name MOM_module_import_name = mom_module_import_name;
fnMOM_module_import_lib MOM_module_import_lib = mom_module_import_lib;
fnMOM_module_import_delayed_end MOM_module_import_delayed_end = mom_module_import_delayed_end;
fnMOM_module_import_delayed_next MOM_module_import_delayed_next = mom_module_import_delayed_next;
fnMOM_module_tls_end MOM_module_tls_end = mom_module_tls_end;
fnMOM_module_tls_next MOM_module_tls_next = mom_module_tls_next;
fnMOM_module_relocation_end MOM_module_relocation_end = mom_module_relocation_end;
fnMOM_module_relocation_next MOM_module_relocation_next = mom_module_relocation_next;

fnMOM_process_module_begin MOM_process_module_begin = winmom_process_module_begin;
fnMOM_process_module_end MOM_process_module_end = winmom_process_module_end;
fnMOM_process_module_next MOM_process_module_next = winmom_process_module_next;

/** \} */
