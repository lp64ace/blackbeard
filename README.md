<div align="center">
	<p align="center">
		<img src="img/logo.png" alt="Bob" width="128"/>
	</p>
</div>

# Portable Executable Loader

Executables sometimes use dynamically linked libraries (DLLs) a bit unorthodoxically in order to overwrite functionality of a given application. These portable executables are nothing more than a sequence of ASM instructions and headers, they are mapped into the remote application memory and then their DllMain is called. The remote thread is then terminated and the loader exists. The portable executable is responsible for attaching in the remote application.

# How it Works

Bob *builds* a remote thread and attaches a triggerable loop that can execute APC code. Each operation that needs to be run remotely on the target process is queued and run through that single thread using Just In Time, Assembly compilation!

* The portable executable is loaded into memory and then parsed to load third-party imports from other dyanmically linked libraries.
* After the third party dependencies of the portable executable are resolved we relocate every pointer to the new base address of the module.
* Every section is copied and the charachteristics resolved to match the expectations, EXECUTABLE, READ, WRITE permissions resolved.
* Exceptions, TLS and cookie procedures are triggered and initialized.
* DllMain is called.

# Issues

There are currently minor known issues with path resolving for schema DLL modules like `ms-api-` and `ms-exec-`, basically SxS needs to be rebuilt!

# Build

Download the repository through github or git!

```sh
git clone https://github.com/lp64ace/bob bob
```

Navigate to the build folder and run cmake

```sh
cmake -G "Virtual Studio 17 2022" /path/to/src
cmake --build . --config Release
```

# Notes

Even though C/C++ functions are not exported to the remote process XORSTR is used to hide literals from the binary because this library is sometimes used internally and functions are called from within the protable executable that is mapped.


