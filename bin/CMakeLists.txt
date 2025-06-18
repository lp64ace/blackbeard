# -----------------------------------------------------------------------------
# Define Include Directories

set(INC
	# Internal Include Directories
	.
	
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
	example.c

)

# -----------------------------------------------------------------------------
# Define Library Dependencies

set(LIB
	# Internal Library Dependencies
	bob
	
	# External Library Dependencies
	
)

# -----------------------------------------------------------------------------
# Declare Library

add_executable(example ${SRC})
target_include_directories(example PUBLIC ${INC})
# target_include_directories(example SYSTEM ${INC_SYS})
target_link_libraries(example ${LIB})

add_compile_definitions(SOURCE_DIR=L\"${CMAKE_CURRENT_SOURCE_DIR}\")
