#include "MEM_guardedalloc.h"

#include "gtest/gtest.h"

namespace {

TEST(Guarded, Malloc) {
	MEM_use_guarded_allocator();

	void *ptr = MEM_mallocN(sizeof(ptrdiff_t), "ptr");
	ASSERT_NE(ptr, (void *)NULL);
	MEM_freeN(ptr);
}

TEST(Guarded, AlignedMalloc) {
	MEM_use_guarded_allocator();

	void *ptr = MEM_mallocN_aligned(sizeof(ptrdiff_t), 16, "ptr");
	ASSERT_NE(ptr, (void *)NULL);
	ASSERT_EQ(reinterpret_cast<uintptr_t>(ptr) % 16, 0);
	MEM_freeN(ptr);
}

TEST(Guarded, Calloc) {
	MEM_use_guarded_allocator();

	void *ptr = MEM_callocN(sizeof(ptrdiff_t), "ptr");
	ASSERT_NE(ptr, (void *)NULL);
	ASSERT_EQ(*(ptrdiff_t *)ptr, (ptrdiff_t)0);
	MEM_freeN(ptr);
}

TEST(Guarded, AlignedCalloc) {
	MEM_use_guarded_allocator();

	void *ptr = MEM_callocN_aligned(sizeof(ptrdiff_t), 16, "ptr");
	ASSERT_NE(ptr, (void *)NULL);
	ASSERT_EQ(reinterpret_cast<uintptr_t>(ptr) % 16, 0);
	ASSERT_EQ(*(ptrdiff_t *)ptr, (ptrdiff_t)0);
	MEM_freeN(ptr);
}

}  // namespace
