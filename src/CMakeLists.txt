# -----------------------------------------------------------------------------
# Define Include Directories

set(INC
	# Internal Include Directories
	PUBLIC .
	PRIVATE ./intern
	
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
	mapper.cc
	mapper.h
	module.c
	module.h
	native.c
	native.h
	process.c
	process.h
	remote.cc
	remote.h
	thread.c
	thread.h
	
	intern/config.h
	intern/list.c
	intern/list.h

)

# -----------------------------------------------------------------------------
# Define Library Dependencies

set(LIB
	# Internal Library Dependencies
	PUBLIC asmjit
	
	# External Library Dependencies
	
)

# -----------------------------------------------------------------------------
# Declare Library

add_library(bob ${SRC})
target_include_directories(bob PUBLIC ${INC})
# target_include_directories(bob SYSTEM ${INC_SYS})
target_link_libraries(bob ${LIB})
