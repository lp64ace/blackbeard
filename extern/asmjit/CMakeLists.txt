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
	a64.h
	arm.h
	asmjit-scope-begin.h
	asmjit-scope-end.h
	asmjit.h
	core.h
	x86.h
	
	arm/a64archtraits_p.h
	arm/a64assembler.cpp
	arm/a64assembler.h
	arm/a64builder.cpp
	arm/a64builder.h
	arm/a64compiler.cpp
	arm/a64compiler.h
	arm/a64emithelper.cpp
	arm/a64emithelper_p.h
	arm/a64emitter.h
	arm/a64formatter.cpp
	arm/a64formatter_p.h
	arm/a64func.cpp
	arm/a64func_p.h
	arm/a64globals.h
	arm/a64instapi.cpp
	arm/a64instapi_p.h
	arm/a64instdb.cpp
	arm/a64instdb.h
	arm/a64instdb_p.h
	arm/a64operand.cpp
	arm/a64operand.h
	arm/a64rapass.cpp
	arm/a64rapass_p.h
	arm/armformatter.cpp
	arm/armformatter_p.h
	arm/armglobals.h
	arm/armoperand.h
	arm/armutils.h
	core/api-build_p.h
	core/api-config.h
	core/archcommons.h
	core/archtraits.cpp
	core/archtraits.h
	core/assembler.cpp
	core/assembler.h
	core/builder.cpp
	core/builder.h
	core/builder_p.h
	core/codebuffer.h
	core/codeholder.cpp
	core/codeholder.h
	core/codewriter.cpp
	core/codewriter_p.h
	core/compiler.cpp
	core/compiler.h
	core/compilerdefs.h
	core/constpool.cpp
	core/constpool.h
	core/cpuinfo.cpp
	core/cpuinfo.h
	core/emithelper.cpp
	core/emithelper_p.h
	core/emitter.cpp
	core/emitter.h
	core/emitterutils.cpp
	core/emitterutils_p.h
	core/environment.cpp
	core/environment.h
	core/errorhandler.cpp
	core/errorhandler.h
	core/formatter.cpp
	core/formatter.h
	core/formatter_p.h
	core/func.cpp
	core/func.h
	core/funcargscontext.cpp
	core/funcargscontext_p.h
	core/globals.cpp
	core/globals.h
	core/inst.cpp
	core/inst.h
	core/instdb.cpp
	core/instdb_p.h
	core/jitallocator.cpp
	core/jitallocator.h
	core/jitruntime.cpp
	core/jitruntime.h
	core/logger.cpp
	core/logger.h
	core/misc_p.h
	core/operand.cpp
	core/operand.h
	core/osutils.cpp
	core/osutils.h
	core/osutils_p.h
	core/raassignment_p.h
	core/rabuilders_p.h
	core/radefs_p.h
	core/ralocal.cpp
	core/ralocal_p.h
	core/rapass.cpp
	core/rapass_p.h
	core/rastack.cpp
	core/rastack_p.h
	core/string.cpp
	core/string.h
	core/support.cpp
	core/support.h
	core/support_p.h
	core/target.cpp
	core/target.h
	core/type.cpp
	core/type.h
	core/virtmem.cpp
	core/virtmem.h
	core/zone.cpp
	core/zone.h
	core/zonehash.cpp
	core/zonehash.h
	core/zonelist.cpp
	core/zonelist.h
	core/zonestack.cpp
	core/zonestack.h
	core/zonestring.h
	core/zonetree.cpp
	core/zonetree.h
	core/zonevector.cpp
	core/zonevector.h
	x86/x86archtraits_p.h
	x86/x86assembler.cpp
	x86/x86assembler.h
	x86/x86builder.cpp
	x86/x86builder.h
	x86/x86compiler.cpp
	x86/x86compiler.h
	x86/x86emithelper.cpp
	x86/x86emithelper_p.h
	x86/x86emitter.h
	x86/x86formatter.cpp
	x86/x86formatter_p.h
	x86/x86func.cpp
	x86/x86func_p.h
	x86/x86globals.h
	x86/x86instapi.cpp
	x86/x86instapi_p.h
	x86/x86instdb.cpp
	x86/x86instdb.h
	x86/x86instdb_p.h
	x86/x86opcode_p.h
	x86/x86operand.cpp
	x86/x86operand.h
	x86/x86rapass.cpp
	x86/x86rapass_p.h

)

# -----------------------------------------------------------------------------
# Define Library Dependencies

set(LIB
	# Internal Library Dependencies
	
	# External Library Dependencies
	
)

# -----------------------------------------------------------------------------
# Declare Library

bob_add_lib(asmjit "${SRC}" "${INC}" "${INC_SYS}" "${LIB}")
add_library(bob::extern::asmjit ALIAS asmjit)

# TODO I do not like this abomination of a library make prebuilt binaries!
