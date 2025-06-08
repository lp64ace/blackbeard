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
	list.c
	list.h
	spoof.asm
	spoof.c
	spoof.h
	xorstr.hh
	variadic.h
	
	asm/a64.h
	asm/arm.h
	asm/asmjit-scope-begin.h
	asm/asmjit-scope-end.h
	asm/asmjit.h
	asm/core.h
	asm/x86.h
	
	asm/arm/a64archtraits_p.h
	asm/arm/a64assembler.cpp
	asm/arm/a64assembler.h
	asm/arm/a64builder.cpp
	asm/arm/a64builder.h
	asm/arm/a64compiler.cpp
	asm/arm/a64compiler.h
	asm/arm/a64emithelper.cpp
	asm/arm/a64emithelper_p.h
	asm/arm/a64emitter.h
	asm/arm/a64formatter.cpp
	asm/arm/a64formatter_p.h
	asm/arm/a64func.cpp
	asm/arm/a64func_p.h
	asm/arm/a64globals.h
	asm/arm/a64instapi.cpp
	asm/arm/a64instapi_p.h
	asm/arm/a64instdb.cpp
	asm/arm/a64instdb.h
	asm/arm/a64instdb_p.h
	asm/arm/a64operand.cpp
	asm/arm/a64operand.h
	asm/arm/a64rapass.cpp
	asm/arm/a64rapass_p.h
	asm/arm/armformatter.cpp
	asm/arm/armformatter_p.h
	asm/arm/armglobals.h
	asm/arm/armoperand.h
	asm/arm/armutils.h
	asm/core/api-build_p.h
	asm/core/api-config.h
	asm/core/archcommons.h
	asm/core/archtraits.cpp
	asm/core/archtraits.h
	asm/core/assembler.cpp
	asm/core/assembler.h
	asm/core/builder.cpp
	asm/core/builder.h
	asm/core/builder_p.h
	asm/core/codebuffer.h
	asm/core/codeholder.cpp
	asm/core/codeholder.h
	asm/core/codewriter.cpp
	asm/core/codewriter_p.h
	asm/core/compiler.cpp
	asm/core/compiler.h
	asm/core/compilerdefs.h
	asm/core/constpool.cpp
	asm/core/constpool.h
	asm/core/cpuinfo.cpp
	asm/core/cpuinfo.h
	asm/core/emithelper.cpp
	asm/core/emithelper_p.h
	asm/core/emitter.cpp
	asm/core/emitter.h
	asm/core/emitterutils.cpp
	asm/core/emitterutils_p.h
	asm/core/environment.cpp
	asm/core/environment.h
	asm/core/errorhandler.cpp
	asm/core/errorhandler.h
	asm/core/formatter.cpp
	asm/core/formatter.h
	asm/core/formatter_p.h
	asm/core/func.cpp
	asm/core/func.h
	asm/core/funcargscontext.cpp
	asm/core/funcargscontext_p.h
	asm/core/globals.cpp
	asm/core/globals.h
	asm/core/inst.cpp
	asm/core/inst.h
	asm/core/instdb.cpp
	asm/core/instdb_p.h
	asm/core/jitallocator.cpp
	asm/core/jitallocator.h
	asm/core/jitruntime.cpp
	asm/core/jitruntime.h
	asm/core/logger.cpp
	asm/core/logger.h
	asm/core/misc_p.h
	asm/core/operand.cpp
	asm/core/operand.h
	asm/core/osutils.cpp
	asm/core/osutils.h
	asm/core/osutils_p.h
	asm/core/raassignment_p.h
	asm/core/rabuilders_p.h
	asm/core/radefs_p.h
	asm/core/ralocal.cpp
	asm/core/ralocal_p.h
	asm/core/rapass.cpp
	asm/core/rapass_p.h
	asm/core/rastack.cpp
	asm/core/rastack_p.h
	asm/core/string.cpp
	asm/core/string.h
	asm/core/support.cpp
	asm/core/support.h
	asm/core/support_p.h
	asm/core/target.cpp
	asm/core/target.h
	asm/core/type.cpp
	asm/core/type.h
	asm/core/virtmem.cpp
	asm/core/virtmem.h
	asm/core/zone.cpp
	asm/core/zone.h
	asm/core/zonehash.cpp
	asm/core/zonehash.h
	asm/core/zonelist.cpp
	asm/core/zonelist.h
	asm/core/zonestack.cpp
	asm/core/zonestack.h
	asm/core/zonestring.h
	asm/core/zonetree.cpp
	asm/core/zonetree.h
	asm/core/zonevector.cpp
	asm/core/zonevector.h
	asm/x86/x86archtraits_p.h
	asm/x86/x86assembler.cpp
	asm/x86/x86assembler.h
	asm/x86/x86builder.cpp
	asm/x86/x86builder.h
	asm/x86/x86compiler.cpp
	asm/x86/x86compiler.h
	asm/x86/x86emithelper.cpp
	asm/x86/x86emithelper_p.h
	asm/x86/x86emitter.h
	asm/x86/x86formatter.cpp
	asm/x86/x86formatter_p.h
	asm/x86/x86func.cpp
	asm/x86/x86func_p.h
	asm/x86/x86globals.h
	asm/x86/x86instapi.cpp
	asm/x86/x86instapi_p.h
	asm/x86/x86instdb.cpp
	asm/x86/x86instdb.h
	asm/x86/x86instdb_p.h
	asm/x86/x86opcode_p.h
	asm/x86/x86operand.cpp
	asm/x86/x86operand.h
	asm/x86/x86rapass.cpp
	asm/x86/x86rapass_p.h

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
