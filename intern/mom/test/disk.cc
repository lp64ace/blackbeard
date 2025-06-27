#include "mom.h"

#include "gtest/gtest.h"

namespace {

#ifdef WIN32
#	define TEST_MODULE_FILE "C:\\Windows\\System32\\kernel32.dll"
#endif

#ifdef UNIX
#	define TEST_MODULE_FILE NULL
#endif

TEST(MomDisk, Sections) {
	ListBase modules = MOM_module_open_by_file(TEST_MODULE_FILE);
	EXPECT_TRUE(!LIB_listbase_is_empty(&modules));
	EXPECT_TRUE(LIB_listbase_is_single(&modules));
	LISTBASE_FOREACH(ModuleHandle *, handle, &modules) {
		ListBase sections = MOM_module_sections(handle);
		LISTBASE_FOREACH(ModuleSection *, section, &sections) {
			EXPECT_EQ(MOM_module_section_name(handle, section)[0], '.');
		}
		EXPECT_GT(LIB_listbase_count(&sections), 0);
	}
	MOM_module_close_collection(&modules);
}

TEST(MomDisk, Exports) {
	ListBase modules = MOM_module_open_by_file(TEST_MODULE_FILE);
	EXPECT_TRUE(!LIB_listbase_is_empty(&modules));
	EXPECT_TRUE(LIB_listbase_is_single(&modules));
	LISTBASE_FOREACH(ModuleHandle *, handle, &modules) {
		ListBase exports = MOM_module_exports(handle);
		LISTBASE_FOREACH(ModuleExport *, exported, &exports) {
			if (!MOM_module_export_is_forward(handle, exported)) {
				EXPECT_NE(MOM_module_export_logical(handle, exported), nullptr);
				EXPECT_EQ(MOM_module_export_physical(handle, exported), nullptr);
			}
		}
		EXPECT_GT(LIB_listbase_count(&exports), 0);
	}
	MOM_module_close_collection(&modules);
}

TEST(MomDisk, Imports) {
	ListBase modules = MOM_module_open_by_file(TEST_MODULE_FILE);
	EXPECT_TRUE(!LIB_listbase_is_empty(&modules));
	EXPECT_TRUE(LIB_listbase_is_single(&modules));
	LISTBASE_FOREACH(ModuleHandle *, handle, &modules) {
		ListBase imports = MOM_module_imports(handle);
		LISTBASE_FOREACH(ModuleImport *, imported, &imports) {
			EXPECT_NE(MOM_module_import_libname(handle, imported), nullptr);
		}
		EXPECT_GT(LIB_listbase_count(&imports), 0);
	}
	MOM_module_close_collection(&modules);
}

TEST(MomDisk, ImportsDelayed) {
	ListBase modules = MOM_module_open_by_file(TEST_MODULE_FILE);
	EXPECT_TRUE(!LIB_listbase_is_empty(&modules));
	EXPECT_TRUE(LIB_listbase_is_single(&modules));
	LISTBASE_FOREACH(ModuleHandle *, handle, &modules) {
		ListBase imports = MOM_module_imports_delayed(handle);
		LISTBASE_FOREACH(ModuleImport *, imported, &imports) {
			EXPECT_NE(MOM_module_import_libname(handle, imported), nullptr);
		}
		EXPECT_GT(LIB_listbase_count(&imports), 0);
	}
	MOM_module_close_collection(&modules);
}

TEST(MomDisk, Relocations) {
	ListBase modules = MOM_module_open_by_file(TEST_MODULE_FILE);
	EXPECT_TRUE(!LIB_listbase_is_empty(&modules));
	EXPECT_TRUE(LIB_listbase_is_single(&modules));
	LISTBASE_FOREACH(ModuleHandle *, handle, &modules) {
		ListBase relocations = MOM_module_relocations(handle);
		LISTBASE_FOREACH(ModuleRelocation *, relocation, &relocations) {
			EXPECT_NE(MOM_module_relocation_type(handle, relocation), MOM_RELOCATION_NONE);
		}
		EXPECT_GT(LIB_listbase_count(&relocations), 0);
	}
	MOM_module_close_collection(&modules);
}

}  // namespace
