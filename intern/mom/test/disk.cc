#include "mom.h"

#include "gtest/gtest.h"

namespace {

#ifdef WIN32
#	define TEST_MODULE_FILE "C:\\Windows\\System32\\kernel32.dll"
#endif

#ifdef UNIX
#	define TEST_MODULE_FILE NULL
#endif

TEST(Mom, DiskSections) {
	ModuleHandle *kernel32 = MOM_module_open_by_file(TEST_MODULE_FILE);
	ASSERT_NE(kernel32, nullptr);
	for (ModuleSection *section = MOM_module_section_begin(kernel32); section != MOM_module_section_end(kernel32); section = MOM_module_section_next(kernel32, section)) {
		const char *name = MOM_module_section_name(kernel32, section);
		EXPECT_EQ(name[0], '.');
		EXPECT_GT(strlen(name), 0);
		EXPECT_LT(strlen(name), 8);
		EXPECT_NE(MOM_module_section_disk(kernel32, section), nullptr) << name;
		EXPECT_EQ(MOM_module_section_memory(kernel32, section), nullptr) << name;
	}
	MOM_module_close(kernel32);
}

TEST(Mom, DiskExports) {
	ModuleHandle *kernel32 = MOM_module_open_by_file(TEST_MODULE_FILE);
	ASSERT_NE(kernel32, nullptr);
	for (ModuleExport *exported = MOM_module_export_begin(kernel32); exported != MOM_module_export_end(kernel32); exported = MOM_module_export_next(kernel32, exported)) {
		const char *name = MOM_module_export_name(kernel32, exported);
		if (name) {
			EXPECT_GE(strlen(name), 0);
			EXPECT_LT(strlen(name), MOM_MAX_EXPNAME_LEN);
			if (!MOM_module_export_lib(kernel32, exported)) {
				EXPECT_NE(MOM_module_export_disk(kernel32, exported), nullptr) << name;
			}
			EXPECT_EQ(MOM_module_export_memory(kernel32, exported), nullptr) << name;
		}
	}
	MOM_module_close(kernel32);
}

TEST(Mom, DiskImports) {
	ModuleHandle *kernel32 = MOM_module_open_by_file(TEST_MODULE_FILE);
	ASSERT_NE(kernel32, nullptr);
	for (ModuleImport *imported = MOM_module_import_begin(kernel32); imported != MOM_module_import_end(kernel32); imported = MOM_module_import_next(kernel32, imported)) {
		const char *lib = MOM_module_import_lib(kernel32, imported);
		if (lib) {
			EXPECT_GE(strlen(lib), 0);
			EXPECT_LT(strlen(lib), MOM_MAX_EXPNAME_LEN);
		}
		const char *name = MOM_module_import_name(kernel32, imported);
		if (name) {
			EXPECT_GE(strlen(name), 0);
			EXPECT_LT(strlen(name), MOM_MAX_EXPNAME_LEN);
		}

		EXPECT_NE(MOM_module_import_to_disk(kernel32, imported), nullptr);
		EXPECT_EQ(MOM_module_import_to_memory(kernel32, imported), nullptr);

		EXPECT_NE(lib, nullptr);
		EXPECT_NE(name, nullptr);
	}
	MOM_module_close(kernel32);
}

TEST(Mom, DiskDelayedImports) {
	ModuleHandle *kernel32 = MOM_module_open_by_file(TEST_MODULE_FILE);
	ASSERT_NE(kernel32, nullptr);
	for (ModuleImport *imported = MOM_module_import_delayed_begin(kernel32); imported != MOM_module_import_delayed_end(kernel32); imported = MOM_module_import_delayed_next(kernel32, imported)) {
		const char *lib = MOM_module_import_lib(kernel32, imported);
		if (lib) {
			EXPECT_GE(strlen(lib), 0);
			EXPECT_LT(strlen(lib), MOM_MAX_EXPNAME_LEN);
		}
		const char *name = MOM_module_import_name(kernel32, imported);
		if (name) {
			EXPECT_GE(strlen(name), 0);
			EXPECT_LT(strlen(name), MOM_MAX_EXPNAME_LEN);
		}

		EXPECT_NE(MOM_module_import_to_disk(kernel32, imported), nullptr);
		EXPECT_EQ(MOM_module_import_to_memory(kernel32, imported), nullptr);

		EXPECT_NE(lib, nullptr);
		EXPECT_NE(name, nullptr);
	}
	MOM_module_close(kernel32);
}

}  // namespace
