#include "manualmap.h"

#include "gtest/gtest.h"

extern "C" const int datatoc_testdll1_dll_size;
extern "C" const char datatoc_testdll1_dll[];

extern "C" const int datatoc_testdll2_dll_size;
extern "C" const char datatoc_testdll2_dll[];

namespace {

// TestDLL 1

TEST(BobManualMap, Local1) {
	ProcessHandle *self = MOM_process_self();
	void *address = NULL;
	if ((address = BOB_manual_map_image(self, datatoc_testdll1_dll, datatoc_testdll1_dll_size, kBobRebaseAlways))) {
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
	if ((address = BOB_manual_map_image(process, datatoc_testdll1_dll, datatoc_testdll1_dll_size, kBobRebaseAlways))) {
		// Do stuff...?
	}
	EXPECT_NE(address, nullptr);

	MOM_process_close_collection(&processes);
}

// TestDLL 2

TEST(BobManualMap, Local2) {
	ProcessHandle *self = MOM_process_self();
	void *address = NULL;
	if ((address = BOB_manual_map_image(self, datatoc_testdll2_dll, datatoc_testdll2_dll_size, kBobRebaseAlways))) {
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
	if ((address = BOB_manual_map_image(process, datatoc_testdll2_dll, datatoc_testdll2_dll_size, kBobRebaseAlways))) {
		// Do stuff...?
	}
	EXPECT_NE(address, nullptr);

	MOM_process_close_collection(&processes);
}

} // namespace
