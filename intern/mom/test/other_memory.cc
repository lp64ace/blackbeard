#include "mom.h"

#include "gtest/gtest.h"

#ifdef WIN32
#include <windows.h>
#endif

namespace {

#ifdef WIN32
#define TEST_MODULE_NAME "kernel32.dll"
#endif

#ifdef UNIX
#define TEST_MODULE_NAME NULL
#endif

TEST(MomOther, Sections) {
	ListBase processes = MOM_process_open_by_name("notepad.exe");
	if (LIB_listbase_is_empty(&processes)) {
		GTEST_SKIP();
	}

	ProcessHandle *process = (ProcessHandle *)processes.first;

	ListBase modules = MOM_module_open_by_name(process, TEST_MODULE_NAME);
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

	MOM_process_close_collection(&processes);
}

TEST(MomOther, Exports) {
	ListBase processes = MOM_process_open_by_name("notepad.exe");
	if (LIB_listbase_is_empty(&processes)) {
		GTEST_SKIP();
	}

	ProcessHandle *process = (ProcessHandle *)processes.first;

	ListBase modules = MOM_module_open_by_name(process, TEST_MODULE_NAME);
	EXPECT_TRUE(!LIB_listbase_is_empty(&modules));
	EXPECT_TRUE(LIB_listbase_is_single(&modules));
	LISTBASE_FOREACH(ModuleHandle *, handle, &modules) {
		ListBase exports = MOM_module_exports(handle);
		LISTBASE_FOREACH(ModuleExport *, exported, &exports) {
			if (!MOM_module_export_is_forward(handle, exported)) {
				EXPECT_NE(MOM_module_export_logical(handle, exported), nullptr);
				EXPECT_NE(MOM_module_export_physical(handle, exported), nullptr);
			}
		}
		EXPECT_GT(LIB_listbase_count(&exports), 0);
	}
	MOM_module_close_collection(&modules);

	MOM_process_close_collection(&processes);
}

TEST(MomOther, Imports) {
	ListBase processes = MOM_process_open_by_name("notepad.exe");
	if (LIB_listbase_is_empty(&processes)) {
		GTEST_SKIP();
	}

	ProcessHandle *process = (ProcessHandle *)processes.first;

	ListBase modules = MOM_module_open_by_name(process, TEST_MODULE_NAME);
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
	
	MOM_process_close_collection(&processes);
}

TEST(MomOther, ImportsDelayed) {
	ListBase processes = MOM_process_open_by_name("notepad.exe");
	if (LIB_listbase_is_empty(&processes)) {
		GTEST_SKIP();
	}

	ProcessHandle *process = (ProcessHandle *)processes.first;

	ListBase modules = MOM_module_open_by_name(process, TEST_MODULE_NAME);
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

	MOM_process_close_collection(&processes);
}

TEST(MomOther, Relocations) {
	ListBase processes = MOM_process_open_by_name("notepad.exe");
	if (LIB_listbase_is_empty(&processes)) {
		GTEST_SKIP();
	}

	ProcessHandle *process = (ProcessHandle *)processes.first;

	ListBase modules = MOM_module_open_by_name(process, TEST_MODULE_NAME);
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

	MOM_process_close_collection(&processes);
}

} // namespace
