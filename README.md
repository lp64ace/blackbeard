<div align="center">
	<p align="center">
		<img src="img/logo.png" alt="Bob" width="128"/>
	</p>
</div>

## 🧠 Manual PE Mappe

**A lightweight PE (Portable Executable) mapper written in C/C++ with CMake support.**
This project allows manual loading of Windows executables (DLLs/EXEs) into memory without relying on LoadLibrary, or any external libraries.

## ✨ Features

- **Manual Mapping** of PE files into memory (DLLs and EXEs)
- **Build from Source** — pure C/C++ and Windows API
- **CMake Build System** for clean and portable builds
- **Complete Relocation & Import Resolution**
- Optional TLS callback support
- Optional Exception callback support
- Clean and readable codebase for educational and practical use

## 📦 Usage Example

```cpp
#include "native.h"
#include "mmap.h"
#include "mod.h"
#include "proc.h"

#include "xorstr.hh"

#include <stdio.h>
#include <stdlib.h>

extern "C" const int datatoc_example_dll_size;
extern "C" const char datatoc_example_dll[];

int main(void) {
	BOB_native_init();
	BobProc *process = BOB_process_open(XORSTR("notepad.exe"));
	if (!process) {
		fprintf(stdout, XORSTR("Notepad.exe is not running...\n"));
		return -1;
	}
	BobModule *address = BOB_mmap_image(process, NULL, datatoc_example_dll, datatoc_example_dll_size, 0);
	if (!address) {
		fprintf(stdout, XORSTR("Failed...\n"));
		return -1;
	}
	BOB_process_close(process);
	BOB_native_exit();
	return 0;
}
```
