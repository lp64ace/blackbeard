#include "manualmap.h"

#include "gtest/gtest.h"

#include <thread>
#include <future>
#include <chrono>

extern "C" {
extern const int datatoc_testdll1_dll_size;
extern const int datatoc_testdll2_dll_size;
extern const int datatoc_testdll3_dll_size;
extern const int datatoc_memallocdll_dll_size;
extern const char datatoc_testdll1_dll[];
extern const char datatoc_testdll2_dll[];
extern const char datatoc_testdll3_dll[];
extern const char datatoc_memallocdll_dll[];
}

namespace {

#define ASSERT_TIMEOUT(code_block, timeout_ms)                                                \
{                                                                                              \
	auto future = std::async(std::launch::async, [&] { code_block });                          \
	if (future.wait_for(std::chrono::milliseconds(timeout_ms)) != std::future_status::ready) { \
		FAIL() << "Timed out after " << timeout_ms << " ms";                                   \
	}                                                                                          \
}

TEST(BobManualMap, Local1) {
	ProcessHandle *self = MOM_process_self();

	ASSERT_TIMEOUT({
		void *address = NULL;
		if ((address = BOB_manual_map_image(self, datatoc_testdll1_dll, datatoc_testdll1_dll_size, BOB_REBASE_ALWAYS))) {
			// Do stuff...?
		}
		EXPECT_NE(address, nullptr);
	}, 3000);

	MOM_process_close(self);
}

TEST(BobManualMap, Other1) {
	ListBase processes = MOM_process_open_by_name("notepad.exe");
	if (LIB_listbase_is_empty(&processes)) {
		GTEST_SKIP();
	}

	ProcessHandle *process = (ProcessHandle *)processes.first;

	ASSERT_TIMEOUT({
		void *address = NULL;
		if ((address = BOB_manual_map_image(process, datatoc_testdll1_dll, datatoc_testdll1_dll_size, BOB_REBASE_ALWAYS))) {
			// Do stuff...?
		}
		EXPECT_NE(address, nullptr);
	}, 3000);

	MOM_process_close_collection(&processes);
}

TEST(BobManualMap, Local2) {
	ProcessHandle *self = MOM_process_self();

	ASSERT_TIMEOUT({
		void *address = NULL;
		if ((address = BOB_manual_map_image(self, datatoc_testdll2_dll, datatoc_testdll2_dll_size, BOB_REBASE_ALWAYS))) {
			// Do stuff...?
		}
		EXPECT_NE(address, nullptr);
	}, 3000);

	MOM_process_close(self);
}

TEST(BobManualMap, Other2) {
	ListBase processes = MOM_process_open_by_name("notepad.exe");
	if (LIB_listbase_is_empty(&processes)) {
		GTEST_SKIP();
	}

	ProcessHandle *process = (ProcessHandle *)processes.first;

	ASSERT_TIMEOUT({
		void *address = NULL;
		if ((address = BOB_manual_map_image(process, datatoc_testdll2_dll, datatoc_testdll2_dll_size, BOB_REBASE_ALWAYS))) {
			// Do stuff...?
		}
		EXPECT_NE(address, nullptr);
	}, 3000);

	MOM_process_close_collection(&processes);
}

TEST(BobManualMap, Local3) {
	ProcessHandle *self = MOM_process_self();

	ASSERT_TIMEOUT({
		void *address = NULL;
		if ((address = BOB_manual_map_image(self, datatoc_testdll3_dll, datatoc_testdll3_dll_size, BOB_REBASE_ALWAYS))) {
			// Do stuff...?
		}
		EXPECT_NE(address, nullptr);
	}, 3000);

	MOM_process_close(self);
}
  
TEST(BobManualMap, Other3) {
	ListBase processes = MOM_process_open_by_name("notepad.exe");
	if (LIB_listbase_is_empty(&processes)) {
		GTEST_SKIP();
	}

	ProcessHandle *process = (ProcessHandle *)processes.first;

	ASSERT_TIMEOUT({
		void *address = NULL;
		if ((address = BOB_manual_map_image(process, datatoc_testdll3_dll, datatoc_testdll3_dll_size, BOB_REBASE_ALWAYS))) {
			// Do stuff...?
		}
		EXPECT_NE(address, nullptr);
	}, 3000);

	MOM_process_close_collection(&processes);
}

TEST(BobManualMap, LocalAlloc) {
	ProcessHandle *self = MOM_process_self();

	ASSERT_TIMEOUT({
		void *address = NULL;
		if ((address = BOB_manual_map_image(self, datatoc_memallocdll_dll, datatoc_memallocdll_dll_size, BOB_REBASE_ALWAYS))) {
			// Do stuff...?
		}
		EXPECT_NE(address, nullptr);
	}, 3000);

	MOM_process_close(self);
}
  
TEST(BobManualMap, OtherAlloc) {
	ListBase processes = MOM_process_open_by_name("notepad.exe");
	if (LIB_listbase_is_empty(&processes)) {
		GTEST_SKIP();
	}

	ProcessHandle *process = (ProcessHandle *)processes.first;

	ASSERT_TIMEOUT({
		void *address = NULL;
		if ((address = BOB_manual_map_image(process, datatoc_memallocdll_dll, datatoc_memallocdll_dll_size, BOB_REBASE_ALWAYS))) {
			// Do stuff...?
		}
		EXPECT_NE(address, nullptr);
	}, 3000);

	MOM_process_close_collection(&processes);
}

} // namespace
