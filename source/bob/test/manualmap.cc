#include "manualmap.h"

#include "gtest/gtest.h"

extern "C" const int datatoc_testdll1_dll_size;
extern "C" const char datatoc_testdll1_dll[];

namespace {

TEST(BobManualMap, Local) {
	ProcessHandle *self = MOM_process_self();
	void *address = NULL;
	if ((address = BOB_manual_map_image(self, datatoc_testdll1_dll, datatoc_testdll1_dll_size, kBobRebaseAlways))) {
		// Do stuff...?
	}
	EXPECT_NE(address, nullptr);
	MOM_process_close(self);
}

TEST(BobManualMap, Other) {
	ListBase processes;
	do {
		processes = MOM_process_open_by_name("notepad.exe"); // Windows 10
		if (!LIB_listbase_is_empty(&processes)) {
			break;
		}

		processes = MOM_process_open_by_name("Notepad.exe"); // Windows 11
		if (!LIB_listbase_is_empty(&processes)) {
			break;
		}

		GTEST_SKIP();
	} while (false);

	ProcessHandle *process = (ProcessHandle *)processes.first;

	void *address = NULL;
	if ((address = BOB_manual_map_image(process, datatoc_testdll1_dll, datatoc_testdll1_dll_size, kBobRebaseAlways))) {
		// Do stuff...?
	}
	EXPECT_NE(address, nullptr);

	MOM_process_close_collection(&processes);
}

} // namespace
