# -----------------------------------------------------------------------------
# Define Include Directories

set(INC
	# Internal Include Directories
	PUBLIC .
	
	# External Include Directories
	
)

# -----------------------------------------------------------------------------
# Define System Include Directories

set(INC_SYS
	# External System Include Directories
	
)

# -----------------------------------------------------------------------------
# Define Source Files

set(SRC
	MEM_guardedalloc.h
	
	intern/utils/memleak.cc
	intern/utils/memleak.h
	intern/utils/memusage.cc
	intern/utils/memusage.h
	intern/guarded_impl.c
	intern/linklist.c
	intern/linklist.h
	intern/lockfree_impl.c
	intern/mallocn.h
	intern/mallocn.c
	intern/mallocn_guarded_private.h
	intern/mallocn_lockfree_private.h
)

# -----------------------------------------------------------------------------
# Define Library Dependencies

set(LIB
	# Internal Library Dependencies
	
	# External Library Dependencies
	${PTHREADS_LIBRARIES}
	
)

# -----------------------------------------------------------------------------
# Declare Library

bob_add_lib(guardedalloc "${SRC}" "${INC}" "${INC_SYS}" "${LIB}")
add_library(bob::intern::guardedalloc ALIAS guardedalloc)

# -----------------------------------------------------------------------------
# Define Include Directories (Test)

set(INC
	# Internal Include Directories
	PUBLIC .
	
	# External Include Directories
	
)

# -----------------------------------------------------------------------------
# Define System Include Directories (Test)

set(INC_SYS
	# External System Include Directories
	
)

# -----------------------------------------------------------------------------
# Define Source Files (Test)

set(TEST
	test/lockfree.cc
	test/guarded.cc
)

# -----------------------------------------------------------------------------
# Define Library Dependencies (Test)

set(LIB
	# Internal Library Dependencies
	bob::intern::guardedalloc
	
	# External Library Dependencies
	${PTHREADS_LIBRARIES}
	
)

# -----------------------------------------------------------------------------
# Declare Test

bob_add_test_executable(guardedalloc "${TEST}" "${INC}" "${INC_SYS}" "${LIB}")
