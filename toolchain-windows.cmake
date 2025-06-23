set(CMAKE_SYSTEM_NAME Windows)
set(CMAKE_SYSTEM_PROCESSOR x86_64)

set(CMAKE_C_COMPILER clang)
set(CMAKE_CXX_COMPILER clang++)

set(CMAKE_LINKER lld-link)

set(CMAKE_C_FLAGS "-target x86_64-pc-windows-msvc --sysroot=/usr/x86_64-w64-mingw32")
set(CMAKE_CXX_FLAGS "-target x86_64-pc-windows-msvc --sysroot=/usr/x86_64-w64-mingw32")

set(CMAKE_EXE_LINKER_FLAGS "-static")

set(CMAKE_EXECUTABLE_SUFFIX ".exe")
set(CMAKE_STATIC_LIBRARY_SUFFIX ".lib")

set(CMAKE_FIND_ROOT_PATH /usr/x86_64-w64-mingw32)

set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
