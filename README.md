<div align="center">
	<p align="center">
		<img src="img/logo.png" alt="Bob" width="128"/>
	</p>
	<h1>Bob</h1>
</div>

Modern manual mapping library with C99-compatible linker support for Portable Executable (PE) modules and DLLs.

## 🚀 Features

* Manual mapping of PE files into remote processes
* Remote thread injection
* Memory patching and function hooking
* Process and module enumeration
* Obfuscation support to evade static signature detection

## 📦 Usage Example

```cpp
#include "native.h"
#include "mmap.h"
#include "mod.h"
#include "remote.h"
#include "proc.h"

#include "xorstr.hh"

#include <stdio.h>
#include <stdlib.h>

extern "C" const int datatoc_creator_dll_size;
extern "C" const char datatoc_creator_dll[];

int main(void) {
	BOB_native_init();
	BobProc *process = BOB_process_open(XORSTR("notepad.exe"));
	if (!process) {
		fprintf(stdout, XORSTR("Notepad.exe is not currently running on this system...\n"));
		return -1;
	}

	BobModule *address = BOB_mmap_image(process, NULL, (const void *)datatoc_creator_dll, datatoc_creator_dll_size, 0);
	if (!address) {
		fprintf(stdout, XORSTR("Failed to manual map module from memory into process...\n"));
		return -1;
	}
	BOB_process_close(process);
	BOB_native_exit();
	return 0;
}
```
