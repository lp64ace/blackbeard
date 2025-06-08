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
	mod.c
	mod.h
	native.cc
	native.h
	proc.c
	proc.h
	remote.cc
	remote.h
	thread.c
	thread.h

)

# -----------------------------------------------------------------------------
# Define Library Dependencies

set(LIB
	# Internal Library Dependencies
	PUBLIC pickles
	
	# External Library Dependencies
	
)

# -----------------------------------------------------------------------------
# Declare Library

add_library(bob ${SRC})
target_include_directories(bob ${INC} ${INC_SYS})
target_link_libraries(bob ${LIB})
