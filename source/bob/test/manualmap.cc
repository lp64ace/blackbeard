#include "defines.h"
#include "list.h"

#include "manualmap.h"

#include "gtest/gtest.h"

extern "C" {
extern const int datatoc_testdll1_dll_size;
extern const int datatoc_testdll2_dll_size;
extern const int datatoc_testdll3_dll_size;
extern const char datatoc_testdll1_dll[];
extern const char datatoc_testdll2_dll[];
extern const char datatoc_testdll3_dll[];
}

namespace {

TEST(BobManualMap, Local1) {
	ProcessHandle *self = MOM_process_self();
	void *address = NULL;
	if ((address = BOB_manual_map_image(self, datatoc_testdll1_dll, datatoc_testdll1_dll_size, BOB_REBASE_ALWAYS))) {
		// Do stuff...?
	}
	EXPECT_NE(address, nullptr);
	MOM_process_close(self);
}

TEST(BobManualMap, Other1) {
	ListBase processes = MOM_process_open_by_name("notepad.exe");
	if (LIB_listbase_is_empty(&processes)) {
		GTEST_SKIP();
	}

	ProcessHandle *process = (ProcessHandle *)processes.first;

	void *address = NULL;
	if ((address = BOB_manual_map_image(process, datatoc_testdll1_dll, datatoc_testdll1_dll_size, BOB_REBASE_ALWAYS))) {
		// Do stuff...?
	}
	EXPECT_NE(address, nullptr);

	MOM_process_close_collection(&processes);
}

TEST(BobManualMap, Local2) {
	ProcessHandle *self = MOM_process_self();
	void *address = NULL;
	if ((address = BOB_manual_map_image(self, datatoc_testdll2_dll, datatoc_testdll2_dll_size, BOB_REBASE_ALWAYS))) {
		// Do stuff...?
	}
	EXPECT_NE(address, nullptr);
	MOM_process_close(self);
}

TEST(BobManualMap, Other2) {
	ListBase processes = MOM_process_open_by_name("notepad.exe");
	if (LIB_listbase_is_empty(&processes)) {
		GTEST_SKIP();
	}

	ProcessHandle *process = (ProcessHandle *)processes.first;

	void *address = NULL;
	if ((address = BOB_manual_map_image(process, datatoc_testdll2_dll, datatoc_testdll2_dll_size, BOB_REBASE_ALWAYS))) {
		// Do stuff...?
	}
	EXPECT_NE(address, nullptr);

	MOM_process_close_collection(&processes);
}

TEST(BobManualMap, Local3) {
	ProcessHandle *self = MOM_process_self();
	void *address = NULL;
	if ((address = BOB_manual_map_image(self, datatoc_testdll3_dll, datatoc_testdll3_dll_size, BOB_REBASE_ALWAYS))) {
		// Do stuff...?
	}
	EXPECT_NE(address, nullptr);
	MOM_process_close(self);
}

TEST(BobManualMap, Other3) {
	ListBase processes = MOM_process_open_by_name("notepad.exe");
	if (LIB_listbase_is_empty(&processes)) {
		GTEST_SKIP();
	}

	ProcessHandle *process = (ProcessHandle *)processes.first;

	void *address = NULL;
	if ((address = BOB_manual_map_image(process, datatoc_testdll3_dll, datatoc_testdll3_dll_size, BOB_REBASE_ALWAYS))) {
		// Do stuff...?
	}
	EXPECT_NE(address, nullptr);

	MOM_process_close_collection(&processes);
}

} // namespace
