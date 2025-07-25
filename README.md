<div align="center">
	<p align="center">
		<img src="logo.png" alt="Bob" width="128"/>
	</p>
</div>

# Portable Executable Loader

Executables sometimes use dynamically linked libraries (DLLs) in order to overwrite functionality of a given application. These portable executables are nothing more than a sequence of ASM instructions and headers, they are mapped into the remote application memory and then their DllMain is called. The remote thread is then terminated and the loader exists. The portable executable is responsible for attaching in the remote application.

# How it Works

Bob *builds* a remote thread and attaches a triggerable loop that can execute APC code. Each operation that needs to be run remotely on the target process is queued and run through that single thread using Just In Time, Assembly compilation!

# Build

Download the repository through github or git!

```sh
git clone https://github.com/lp64ace/bob bob
```

Navigate to the build folder and run cmake

```sh
cmake -G "Virtual Studio 17 2022" /path/to/src
```

# Contribute

There are several TODO tags all over the source code, the project also is in desperate need of proper testing suites for both x86_64 and x64 architectures that can both be simulated using llvm.
Milestones
 - Win32 Architecture test pipeline
 - Naive shellcode replacement for asmjit
 - Linux support
