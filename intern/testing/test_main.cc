#include "MEM_guardedalloc.h"
#include "gtest/gtest.h"

int main(int argc, char **argv) {
	MEM_init_memleak_detection();
	testing::InitGoogleTest(&argc, argv);

	return RUN_ALL_TESTS();
}
