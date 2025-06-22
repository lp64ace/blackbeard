#include "manualmap.h"

#include "gtest/gtest.h"

namespace {

extern "C" const int datatoc_testdll1_dll_size;
extern "C" const char datatoc_testdll1_dll[];

TEST(BobManualMap, Simple) {
	ProcessHandle *self = MOM_process_self();
	void *address = NULL;
	if ((address = BOB_manual_map_image(self, datatoc_testdll1_dll, datatoc_testdll1_dll_size, kBobRebaseAlways))) {
		// Do stuff...?
	}
	EXPECT_NE(address, nullptr);
	MOM_process_close(self);
}

} // namespace
