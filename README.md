<div align="center">
	<p align="center">
		<img src="img/logo.png" alt="Bob" width="128"/>
	</p>
	<h1>Bob</h1>
	<p>
		<b>Note</b>: This library is currently under construction. Its purpose is to provide virtual memory manipulation capabilities on Windows systems, with applications in advanced tasks such as module injection, hooking, remote code execution, and malware analysis or development.
	</p>
</div>

<div align="center">
	<h1>Usage</h1>
	<p>
		<b>Note</b>: The library leverages CMake for building, statically building and linking this library simply won't work!
		It is recommended to use CMake on your project and link the library, the output will change each time you compile to avoid signature detection!
		Needless to say most of the functions here required administrator privillages to operate correctly!
	</p>
</div>

---

## 🚀 Features

* Manual mapping of PE files into remote processes
* Remote thread injection
* Memory patching and function hooking
* Process and module enumeration
* Obfuscation support to avoid static signature detection

---

## ⚙️ Build Instructions

> **Note:** This library uses **CMake** for building. Attempting to build and link it manually (e.g., static linking) will **not work** properly.

* You must use CMake to build and integrate Bob into your project.
* The compiled output is intentionally varied each build to help evade signature detection mechanisms.
* Many of the library's functions require **administrator privileges**.

---

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

	BobModule *module = BOB_mmap_image(process, NULL, (const void *)datatoc_creator_dll, datatoc_creator_dll_size, 0);
	if (!module) {
		fprintf(stdout, XORSTR("Failed to manual map module from memory into process...\n"));
		return -1;
	}
	BOB_process_close(process);
	BOB_native_exit();
	return 0;
}
```

---

## ⚠️ Disclaimer

This project is intended for educational and research purposes only. The author is not responsible for any misuse of this library. Use responsibly and within the bounds of applicable laws.
