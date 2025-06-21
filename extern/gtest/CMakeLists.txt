# -----------------------------------------------------------------------------
# Declare Include Directories

set(INC
	# Common Include Directories
	.
	
	# Internal Include Directories
	PUBLIC ./include
	
)

# -----------------------------------------------------------------------------
# Declare System Include Directories

set(INC_SYS
	# External Include Directories

)

# -----------------------------------------------------------------------------
# Declare Source Files

set(SRC
	include/gtest/gtest-death-test.h
	include/gtest/gtest-matchers.h
	include/gtest/gtest-message.h
	include/gtest/gtest-param-test.h
	include/gtest/gtest-printers.h
	include/gtest/gtest-spi.h
	include/gtest/gtest-test-part.h
	include/gtest/gtest-typed-test.h
	include/gtest/gtest.h
	include/gtest/gtest_pred_impl.h
	include/gtest/gtest_prod.h
	include/gtest/internal/gtest-death-test-internal.h
	include/gtest/internal/gtest-filepath.h
	include/gtest/internal/gtest-internal.h
	include/gtest/internal/gtest-param-util.h
	include/gtest/internal/gtest-port-arch.h
	include/gtest/internal/gtest-port.h
	include/gtest/internal/gtest-string.h
	include/gtest/internal/gtest-type-util.h
	include/gtest/internal/custom/gtest-port.h
	include/gtest/internal/custom/gtest-printers.h
	include/gtest/internal/custom/gtest.h
	src/gtest-death-test.cc
	src/gtest-filepath.cc
	src/gtest-internal-inl.h
	src/gtest-matchers.cc
	src/gtest-port.cc
	src/gtest-printers.cc
	src/gtest-test-part.cc
	src/gtest-typed-test.cc
	src/gtest.cc
	
	# src/gtest-all.cc
	# src/gtest_main.cc
)

# -----------------------------------------------------------------------------
# Declare Library Dependencies

set(LIB
	# Internal Include Directories
	
	# External Include Directories
	
)

# -----------------------------------------------------------------------------
# Declare Library

bob_add_lib(gtests "${SRC}" "${INC}" "${INC_SYS}" "${LIB}")
add_library(bob::extern::gtest ALIAS gtests)
