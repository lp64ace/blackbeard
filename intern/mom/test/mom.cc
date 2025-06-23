#include "mom.h"

#include "gtest/gtest.h"

namespace {

#ifdef WIN32
#	define TEST_MODULE_FILE "C:\\Windows\\System32\\kernel32.dll"
#	define TEST_MODULE_NAME "kernel32.dll"
#	define WIN32_LEAN_AND_MEAN
#	include <windows.h>
#endif

#ifdef UNIX
#	define TEST_MODULE_FILE NULL
#	define TEST_MODULE_NAME NULL
#endif

}  // namespace
