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
	config.h
	spoof.asm
	spoof.c
	spoof.h
	xorstr.hh
	variadic.h

)

# -----------------------------------------------------------------------------
# Define Library Dependencies

set(LIB
	# Internal Library Dependencies
	
	# External Library Dependencies
	
)

# -----------------------------------------------------------------------------
# Declare Library

add_library(pickles ${SRC})
target_include_directories(pickles ${INC} ${INC_SYS})
target_link_libraries(pickles ${LIB})
