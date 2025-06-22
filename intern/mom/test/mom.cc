#include "mom.h"

#include "gtest/gtest.h"

namespace {

#ifdef WIN32
#	define TEST_MODULE_FILE "C:\\Windows\\System32\\kernel32.dll"
#	define TEST_MODULE_NAME "kernel32.dll"
#	define WIN32_LEAN_AND_MEAN
#	include <windows.h>
#endif

#ifdef UNIX
#	define TEST_MODULE_FILE NULL
#	define TEST_MODULE_NAME NULL
#endif

bool mom_resolve_import(const char *libname, const char *name, int maxhops = 4) {
	if (maxhops < 0) {
		return false;
	}

	ModuleHandle *handle = MOM_module_open_by_file(libname);
	if (!handle) {
#ifdef WIN32
		HMODULE hmodule = LoadLibrary(libname);
		if (!hmodule) {
			/**
			 * We failed to find the library though the schema table but windows cannot find it either!
			 */
			return true;
		}
		FreeLibrary(hmodule);
#endif
		return false;
	}

	ModuleExport *exported = NULL;

	bool found = false;

	for (ModuleHandle *itr = handle; itr; itr = MOM_module_next(itr)) {
		if (reinterpret_cast<uintptr_t>(name) < 0xFFFF) {
			exported = MOM_module_export_find_by_ordinal(itr, reinterpret_cast<int>(name));
		}
		else {
			exported = MOM_module_export_find_by_name(itr, name);
		}

		if (exported) {
			if (MOM_module_export_lib(itr, exported)) {
				if (MOM_module_export_forward_name(itr, exported)) {
					found |= mom_resolve_import(MOM_module_export_lib(itr, exported), MOM_module_export_forward_name(itr, exported), maxhops - 1);
				}
				else {
					found |= mom_resolve_import(MOM_module_export_lib(itr, exported), reinterpret_cast<const char *>(MOM_module_export_forward_ordinal(itr, exported)), maxhops - 1);
				}
			}
			else {
				found |= true;
			}
		}
	}

	MOM_module_close_collection(handle);

	return found;
}

TEST(Mom, DependencyDisk) {
	ModuleHandle *kernel32 = MOM_module_open_by_file(TEST_MODULE_FILE);
	ASSERT_NE(kernel32, nullptr);
	for (ModuleImport *imported = MOM_module_import_begin(kernel32); imported != MOM_module_import_end(kernel32); imported = MOM_module_import_next(kernel32, imported)) {
		const char *libname = MOM_module_import_lib(kernel32, imported);
		if (libname) {
			if (MOM_module_import_name(kernel32, imported)) {
				const char *impname = MOM_module_import_name(kernel32, imported);
				EXPECT_TRUE(mom_resolve_import(libname, impname)) << libname << " " << impname;
			}
			else {
				int impordinal = MOM_module_import_ordinal(kernel32, imported);
				EXPECT_TRUE(mom_resolve_import(libname, reinterpret_cast<const char *>(impordinal))) << libname << " " << impordinal;
			}
		}
	}
	for (ModuleImport *imported = MOM_module_import_delayed_begin(kernel32); imported != MOM_module_import_delayed_end(kernel32); imported = MOM_module_import_delayed_next(kernel32, imported)) {
		const char *libname = MOM_module_import_lib(kernel32, imported);
		if (libname) {
			if (MOM_module_import_name(kernel32, imported)) {
				const char *impname = MOM_module_import_name(kernel32, imported);
				EXPECT_TRUE(mom_resolve_import(libname, impname)) << libname << " " << impname;
			} else {
				int impordinal = MOM_module_import_ordinal(kernel32, imported);
				EXPECT_TRUE(mom_resolve_import(libname, reinterpret_cast<const char *>(impordinal))) << libname << " " << impordinal;
			}
		}
	}
	MOM_module_close_collection(kernel32);
}

TEST(Mom, DependencyMemory) {
	ProcessHandle *self = MOM_process_self();
	do {
		ModuleHandle *kernel32 = MOM_module_open_by_name(self, TEST_MODULE_FILE);
		ASSERT_NE(kernel32, nullptr);
		for (ModuleImport *imported = MOM_module_import_begin(kernel32); imported != MOM_module_import_end(kernel32); imported = MOM_module_import_next(kernel32, imported)) {
			const char *libname = MOM_module_import_lib(kernel32, imported);
			if (libname) {
				if (MOM_module_import_name(kernel32, imported)) {
					const char *impname = MOM_module_import_name(kernel32, imported);
					EXPECT_TRUE(mom_resolve_import(libname, impname)) << libname << " " << impname;
				} else {
					int impordinal = MOM_module_import_ordinal(kernel32, imported);
					EXPECT_TRUE(mom_resolve_import(libname, reinterpret_cast<const char *>(impordinal))) << libname << " " << impordinal;
				}
			}
		}
		for (ModuleImport *imported = MOM_module_import_delayed_begin(kernel32); imported != MOM_module_import_delayed_end(kernel32); imported = MOM_module_import_delayed_next(kernel32, imported)) {
			const char *libname = MOM_module_import_lib(kernel32, imported);
			if (libname) {
				if (MOM_module_import_name(kernel32, imported)) {
					const char *impname = MOM_module_import_name(kernel32, imported);
					EXPECT_TRUE(mom_resolve_import(libname, impname)) << libname << " " << impname;
				} else {
					int impordinal = MOM_module_import_ordinal(kernel32, imported);
					EXPECT_TRUE(mom_resolve_import(libname, reinterpret_cast<const char *>(impordinal))) << libname << " " << impordinal;
				}
			}
		}
		MOM_module_close_collection(kernel32);
	} while (false);
	MOM_process_close(self);
}

}  // namespace
