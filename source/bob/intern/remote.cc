#include "MEM_guardedalloc.h"

#include "defines.h"
#include "mom.h"
#include "remote.h"

#define ASMJIT_STATIC
#include "core.h"
#include "x86.h"
#include "a64.h"

#ifndef min
#	define min(a, b) (((a) < (b)) ? (a) : (b))
#endif
#ifndef max
#	define max(a, b) (((a) > (b)) ? (a) : (b))
#endif

/* -------------------------------------------------------------------- */
/** \name Internal
 * \{ */

class RemoteWorkerImplementation {
	struct Header {
		uint64_t manifest;
		uint64_t cookie;
		uint64_t saved[8];
	};

	struct Param {
		struct Param *prev, *next;

		uint64_t imm;
		eBobArgumentDeref ref; // More like deref but I like to keep names equal-length!
	};

protected:
	static void begin_call64(asmjit::x86::Assembler &ASM) {
		if (!ASM.is64Bit()) {
			return;
		}

		ASM.sub(asmjit::x86::rsp, asmjit::imm(0x28));

		ASM.mov(asmjit::x86::qword_ptr(asmjit::x86::rsp, 0x8), asmjit::x86::rcx);  // MOV [RSP + 0x08], RCX
		ASM.mov(asmjit::x86::qword_ptr(asmjit::x86::rsp, 0x10), asmjit::x86::rdx); // MOV [RSP + 0x10], RDX
		ASM.mov(asmjit::x86::qword_ptr(asmjit::x86::rsp, 0x18), asmjit::x86::r8);  // MOV [RSP + 0x18], R8
		ASM.mov(asmjit::x86::qword_ptr(asmjit::x86::rsp, 0x20), asmjit::x86::r9);  // MOV [RSP + 0x20], R9
	}

	static void end_call64(asmjit::x86::Assembler &ASM) {
		if (!ASM.is64Bit()) {
			return;
		}

		ASM.mov(asmjit::x86::rcx, asmjit::x86::qword_ptr(asmjit::x86::rsp, 0x08)); // MOV RCX, QWORD PTR [RSP + 0x08]
		ASM.mov(asmjit::x86::rdx, asmjit::x86::qword_ptr(asmjit::x86::rsp, 0x10)); // MOV RDX, QWORD PTR [RSP + 0x10]
		ASM.mov(asmjit::x86::r8, asmjit::x86::qword_ptr(asmjit::x86::rsp, 0x18));  // MOV R8 , QWORD PTR [RSP + 0x18]
		ASM.mov(asmjit::x86::r9, asmjit::x86::qword_ptr(asmjit::x86::rsp, 0x20));  // MOV R9 , QWORD PTR [RSP + 0x20]

		ASM.add(asmjit::x86::rsp, asmjit::imm(0x28));
		ASM.ret();
	}

	static void store(asmjit::x86::Assembler &ASM, const asmjit::x86::Gp &reg, Param *param) {
		switch (param->ref) {
			case kBobDeref: {
				if (ASM.is64Bit()) {
					ASM.mov(asmjit::x86::rax, asmjit::imm(param->imm));
					ASM.mov(reg, asmjit::x86::qword_ptr(asmjit::x86::rax));
				} else {
					ASM.mov(asmjit::x86::eax, asmjit::imm(param->imm));
					ASM.mov(reg, asmjit::x86::dword_ptr(asmjit::x86::eax));
				}
			} break;
			case kBobDeref4: {
				if (ASM.is64Bit()) {
					ASM.mov(asmjit::x86::rax, asmjit::imm(param->imm));
					ASM.mov(reg, asmjit::x86::dword_ptr(asmjit::x86::rax));
				} else {
					ASM.mov(asmjit::x86::eax, asmjit::imm(param->imm));
					ASM.mov(reg, asmjit::x86::dword_ptr(asmjit::x86::eax));
				}
			} break;
			case kBobDeref8: {
				if (ASM.is64Bit()) {
					ASM.mov(asmjit::x86::rax, asmjit::imm(param->imm));
					ASM.mov(reg, asmjit::x86::qword_ptr(asmjit::x86::rax));
				} else {
					// ASM.mov(asmjit::x86::eax, param->imm);
					// ASM.mov(reg, asmjit::x86::qword_ptr(asmjit::x86::eax));
				}
			} break;
			default: {
				ASM.mov(reg, asmjit::imm(param->imm));
			} break;
		}
	}

	static void push(asmjit::x86::Assembler &ASM, Param *param) {
		if (ASM.is64Bit()) {
			store(ASM, asmjit::x86::rbx, param);
			ASM.push(asmjit::x86::rbx);
		} else {
			store(ASM, asmjit::x86::ebx, param);
			ASM.push(asmjit::x86::ebx);
		}
	}

	void call(asmjit::x86::Assembler &ASM, const void *procedure) {
		size_t nparams = LIB_listbase_count(&this->params);

		if (ASM.is64Bit()) {
			size_t diff = max(nparams, 4) * sizeof(uintptr_t) + sizeof(uintptr_t); // args + return
			diff = (diff + 0x10) & ~0xF;

			ASM.sub(asmjit::x86::rsp, asmjit::imm(diff)); // SUB RSP, diff
			Param *p = static_cast<Param *>(this->params.first);
			if ((p = static_cast<Param *>(LIB_pophead(&this->params)))) { // RCX
				store(ASM, asmjit::x86::rcx, p);
				MEM_freeN(p);
			}
			if ((p = static_cast<Param *>(LIB_pophead(&this->params)))) { // RDX
				store(ASM, asmjit::x86::rdx, p);
				MEM_freeN(p);
			}
			if ((p = static_cast<Param *>(LIB_pophead(&this->params)))) { // R8
				store(ASM, asmjit::x86::r8, p);
				MEM_freeN(p);
			}
			if ((p = static_cast<Param *>(LIB_pophead(&this->params)))) { // R9
				store(ASM, asmjit::x86::r9, p);
				MEM_freeN(p);
			}

			while ((p = static_cast<Param *>(LIB_poptail(&this->params)))) {
				push(ASM, p);
				MEM_freeN(p);
			}

			ASM.mov(asmjit::x86::r13, asmjit::imm(procedure));
			ASM.call(asmjit::x86::r13);
			ASM.add(asmjit::x86::rsp, asmjit::imm(diff)); // ADD RSP, diff
		} else {
			if (nparams < 2) {
				Param *p = static_cast<Param *>(this->params.first);
				if ((p = static_cast<Param *>(LIB_pophead(&this->params)))) { // EDX
					store(ASM, asmjit::x86::edx, p);
					MEM_freeN(p);
				}

				stdcall(ASM, procedure);
			}

			Param *p = static_cast<Param *>(this->params.first);
			if ((p = static_cast<Param *>(LIB_pophead(&this->params)))) { // EDX
				store(ASM, asmjit::x86::edx, p);
				MEM_freeN(p);
			}
			if ((p = static_cast<Param *>(LIB_pophead(&this->params)))) { // EAX
				store(ASM, asmjit::x86::eax, p);
				MEM_freeN(p);
			}

			while ((p = static_cast<Param *>(LIB_poptail(&this->params)))) {
				push(ASM, p);
				MEM_freeN(p);
			}

			ASM.mov(asmjit::x86::ebx, asmjit::imm(procedure));
			ASM.call(asmjit::x86::ebx);
		}

		LIB_listbase_clear(&this->params);
	}

	void stdcall(asmjit::x86::Assembler &ASM, const void *procedure) {
		Param *p;
		while ((p = static_cast<Param *>(LIB_poptail(&this->params)))) {
			push(ASM, p);
			MEM_freeN(p);
		}

		ASM.mov(asmjit::x86::eax, asmjit::imm(procedure));
		ASM.call(asmjit::x86::eax);

		LIB_listbase_clear(&this->params);
	}

	void fastcall(asmjit::x86::Assembler &ASM, const void *procedure) {
		// WIN64 call convention and fastcall call convention is the same thing!
		call(ASM, procedure);

		LIB_listbase_clear(&this->params);
	}

	void thiscall(asmjit::x86::Assembler &ASM, const void *procedure) {
		Param *p = static_cast<Param *>(this->params.first);
		if ((p = static_cast<Param *>(LIB_pophead(&this->params)))) { // ECX
			store(ASM, asmjit::x86::ecx, p);
			MEM_freeN(p);
		}

		while ((p = static_cast<Param *>(LIB_poptail(&this->params)))) {
			push(ASM, p);
			MEM_freeN(p);
		}

		ASM.mov(asmjit::x86::eax, asmjit::imm(procedure));
		ASM.call(asmjit::x86::eax);

		LIB_listbase_clear(&this->params);
	}

public:
	RemoteWorkerImplementation(ProcessHandle *process, eMomArchitecture arch) : process(process), asmruntime(), codeholder(), thread(NULL) {
		switch (arch) {
			case kMomArchitectureAmd32: {
				this->codeholder.init(asmjit::Environment(asmjit::Arch::kX86), asmruntime.cpuFeatures());
			} break;
			case kMomArchitectureAmd64: {
				this->codeholder.init(asmjit::Environment(asmjit::Arch::kX64), asmruntime.cpuFeatures());
			} break;
		}

		this->loop = MOM_process_allocate(process, NULL, 0x1000, kMomProtectRead | kMomProtectWrite | kMomProtectExec); // 4KB
		this->code = MOM_process_allocate(process, NULL, 0x1000, kMomProtectRead | kMomProtectWrite | kMomProtectExec); // 4KB
		this->user = MOM_process_allocate(process, NULL, 0x400000, kMomProtectRead | kMomProtectWrite);                 // 4MB
		this->offset = sizeof(Header);

		LIB_listbase_clear(&this->params);
	}

	~RemoteWorkerImplementation() {
		MOM_thread_terminate(this->thread, 0);
		MOM_thread_close(this->thread);

		MOM_process_free(process, this->loop);
		MOM_process_free(process, this->code);
		MOM_process_free(process, this->user);
	}

	void begin_call64() {
		asmjit::x86::Assembler ASM(&this->codeholder);

		this->begin_call64(ASM);
	}

	void end_call64() {
		asmjit::x86::Assembler ASM(&this->codeholder);

		this->end_call64(ASM);
	}

	void call(const void *procedure) {
		asmjit::x86::Assembler ASM(&this->codeholder);

		this->call(ASM, procedure);
	}

	void stdcall(const void *procedure) {
		asmjit::x86::Assembler ASM(&this->codeholder);

		this->stdcall(ASM, procedure);
	}

	void fastcall(const void *procedure) {
		asmjit::x86::Assembler ASM(&this->codeholder);

		this->fastcall(ASM, procedure);
	}

	void thiscall(const void *procedure) {
		asmjit::x86::Assembler ASM(&this->codeholder);

		this->thiscall(ASM, procedure);
	}

	void int3() {
		asmjit::x86::Assembler ASM(&this->codeholder);

		ASM.int3();
	}

	void push(uint64_t imm, eBobArgumentDeref ref) {
		Param *p = static_cast<Param *>(MEM_mallocN(sizeof(Param), "Param"));

		p->imm = imm;
		p->ref = ref;

		LIB_addtail(&this->params, p);
	}

	void *write(const void *buffer, size_t size) {
		void *address = POINTER_OFFSET(this->user, this->offset);
		if (buffer) {
			MOM_process_write(this->process, address, buffer, size);
		}
		this->offset = this->offset + size;
		return address;
	}

	bool init() {
		// !CAUTION! Different codeholder within this context for important reasons!
		asmjit::CodeHolder codeholder;
		codeholder.init(this->codeholder.environment(), this->asmruntime.cpuFeatures());

		if (!(this->evtlocal = MOM_event_open(NULL))) {
			return false;
		}
		if (!(this->evtremote = (void *)MOM_event_share(this->evtlocal, this->process))) {
			return false;
		}

		ModuleHandle *kernel32 = MOM_process_module_find_by_name(this->process, "kernel32.dll");
		ModuleExport *sleepex = MOM_module_export_find_by_name(kernel32, "SleepEx");
		void *_SleepEx = MOM_module_export_physical(kernel32, sleepex);

		asmjit::x86::Assembler ASM(&codeholder);

		if (ASM.is64Bit()) {
			begin_call64(ASM);
		}

		asmjit::Label loop = ASM.newLabel();
		ASM.bind(loop);
		{
			push(0x05, kBobNoDeref);
			push(0x01, kBobNoDeref);
			call(ASM, _SleepEx);
		}
		ASM.jmp(loop);

		if (ASM.is64Bit()) {
			end_call64(ASM);
		}

		asmjit::Section *section = codeholder.sectionById(0);
		asmjit::CodeBuffer buffer = section->buffer();

		if (!MOM_process_write(this->process, this->loop, buffer.data(), buffer.size())) {
			return false;
		}

		this->thread = MOM_thread_spawn(this->process, this->loop, NULL);

		return true;
	}

	void *make() {
		for (size_t index = 0; index < this->codeholder.sectionCount(); index++) {
			asmjit::Section *section = this->codeholder.sectionById(index);
			if (section) {
				asmjit::CodeBuffer buffer = section->buffer();

				/*
				 * We should handle better multiple sections and not just write the last one!
				 */
				if (!MOM_process_write(this->process, this->code, buffer.data(), buffer.size())) {
					return NULL;
				}
			}
		}

		this->codeholder.reset(asmjit::ResetPolicy::kHard);
		this->codeholder.init(this->asmruntime.environment(), this->asmruntime.cpuFeatures());

		return this->code;
	}

	ProcessHandle *host() const {
		return this->process;
	}

	ThreadHandle *worker() const {
		return this->thread;
	}

	void *ptrsave(size_t index) const {
		return POINTER_OFFSET(this->user, offsetof(Header, saved[index]));
	}

	void *ptrcookie(void) const {
		return POINTER_OFFSET(this->user, offsetof(Header, cookie));
	}

	void *ptrmanifest(void) const {
		return POINTER_OFFSET(this->user, offsetof(Header, manifest));
	}

	void save(int index) {
		asmjit::x86::Assembler ASM(&this->codeholder);

		/**
		 * Write the current return value into internal data.
		 */
		void *ret = this->ptrsave(index);
		if (ASM.is64Bit()) {
			ASM.mov(asmjit::x86::rdx, asmjit::imm(reinterpret_cast<uint64_t>(ret)));
			ASM.mov(asmjit::x86::qword_ptr(asmjit::x86::rdx), asmjit::x86::rax);
		} else {
			ASM.mov(asmjit::x86::edx, asmjit::imm(POINTER_AS_UINT(ret)));
			ASM.mov(asmjit::x86::dword_ptr(asmjit::x86::edx), asmjit::x86::eax);
		}
	}

	void notify() {
		asmjit::x86::Assembler ASM(&this->codeholder);

		ModuleHandle *kernel32 = MOM_process_module_find_by_name(this->process, "kernel32.dll");
		ModuleExport *setevent = MOM_module_export_find_by_name(kernel32, "SetEvent");
		void *_SetEvent = MOM_module_export_physical(kernel32, setevent);

		if (ASM.is64Bit()) {
			ASM.mov(asmjit::x86::rcx, asmjit::imm(this->evtremote)); // rcx = HANDLE
			ASM.mov(asmjit::x86::rax, asmjit::imm(_SetEvent));       // rax = &SetEvent
			ASM.call(asmjit::x86::rax);                              // call SetEvent(rcx)
		} else {
			// On x86, SetEvent uses stdcall: push HANDLE, then call
			ASM.push(asmjit::imm(this->evtremote));            // push HANDLE
			ASM.mov(asmjit::x86::eax, asmjit::imm(_SetEvent)); // eax = &SetEvent
			ASM.call(asmjit::x86::eax);                        // call SetEvent
		}
	}

	uint64_t invoke(void *argument) {
		void *code;
		if ((code = this->make())) {
			MOM_thread_queue_apc(thread, code, argument);
			if (!MOM_event_wait(evtlocal, 3000)) {
				// return 0;
			}
			MOM_event_reset(this->evtlocal);
			/**
			 * Because when the event is triggered the stack has not been fully cleared yet,
			 * we need to wait a little bit longer so that the RSP can be re-aligned again!
			 */
			if (!MOM_event_wait(evtlocal, 1)) {
				// return 0;
			}

			uint64_t ret;
			MOM_process_read(this->process, this->ptrsave(0), &ret, sizeof(ret));
			return ret;
		}
		return 0;
	}

private:
	EventHandle *evtlocal = NULL;
	ProcessHandle *process = NULL;
	ThreadHandle *thread = NULL;

	asmjit::JitRuntime asmruntime;
	asmjit::CodeHolder codeholder;

	void *evtremote = NULL;

	void *loop = NULL;
	void *code = NULL;
	void *user = NULL;

	size_t offset = 0;

	ListBase params;
};

RemoteWorker *wrap(class RemoteWorkerImplementation *self) {
	return reinterpret_cast<RemoteWorker *>(self);
}
const RemoteWorker *wrap(const class RemoteWorkerImplementation *self) {
	return reinterpret_cast<const RemoteWorker *>(self);
}

RemoteWorkerImplementation *unwrap(struct RemoteWorker *self) {
	return reinterpret_cast<RemoteWorkerImplementation *>(self);
}
const RemoteWorkerImplementation *unwrap(const struct RemoteWorker *self) {
	return reinterpret_cast<const RemoteWorkerImplementation *>(self);
}

/** \} */

/* -------------------------------------------------------------------- */
/** \name Implementation
 * \{ */

RemoteWorker *BOB_remote_worker_open(ProcessHandle *process, eMomArchitecture architecture) {
	RemoteWorkerImplementation *self = MEM_new<RemoteWorkerImplementation>("RemoteWorker", process, architecture);
	if (!self->init()) {
		BOB_remote_worker_close(wrap(self));
		self = nullptr;
	}
	return wrap(self);
}

void BOB_remote_worker_close(RemoteWorker *worker) {
	MEM_delete<RemoteWorkerImplementation>(unwrap(worker));
}

/** \} */

/* -------------------------------------------------------------------- */
/** \name Internal
 * \{ */

void *BOB_remote_write_ex(RemoteWorker *worker, const void *buffer, size_t size) {
	return unwrap(worker)->write(buffer, size);
}

void *BOB_remote_push_ex(RemoteWorker *worker, const void *buffer, size_t size) {
	void *address = BOB_remote_write_ex(worker, buffer, size);
	BOB_remote_push(worker, reinterpret_cast<uint64_t>(address), kBobNoDeref);
	return address;
}

void BOB_remote_push(RemoteWorker *worker, uint64_t arg, eBobArgumentDeref deref) {
	unwrap(worker)->push(arg, deref);
}

void *BOB_remote_push_ansi(RemoteWorker *worker, const char *buffer) {
	return BOB_remote_push_ex(worker, buffer, sizeof(char) * (strlen(buffer) + 1));
}

void *BOB_remote_push_wide(RemoteWorker *worker, const wchar_t *buffer) {
	return BOB_remote_push_ex(worker, buffer, sizeof(wchar_t) * (wcslen(buffer) + 1));
}

void BOB_remote_begin64(RemoteWorker *worker) {
	unwrap(worker)->begin_call64();
}

void BOB_remote_call(RemoteWorker *worker, eBobCallConvention convention, const void *procedure) {
	switch (convention) {
		case kBobWin64: {
			unwrap(worker)->call(procedure);
		} break;
		case kBobFastcall: {
			unwrap(worker)->fastcall(procedure);
		} break;
		case kBobStdcall: {
			unwrap(worker)->stdcall(procedure);
		} break;
		case kBobThiscall: {
			unwrap(worker)->thiscall(procedure);
		} break;
	}
}

void BOB_remote_notify(RemoteWorker *worker) {
	unwrap(worker)->notify();
}

void BOB_remote_end64(RemoteWorker *worker) {
	unwrap(worker)->end_call64();
}

uint64_t BOB_remote_exec(RemoteWorker *remote, void *argument) {
	return unwrap(remote)->invoke(argument);
}

void BOB_remote_save(RemoteWorker *worker, int index) {
	unwrap(worker)->save(index);
}

uint64_t BOB_remote_saved(RemoteWorker *worker, int index) {
	uint64_t ret;

	void *ptr = unwrap(worker)->ptrsave(index);
	MOM_process_read(unwrap(worker)->host(), ptr, &ret, sizeof(ret));
	return ret;
}

int BOB_remote_thread(RemoteWorker *worker) {
	return MOM_thread_identifier(unwrap(worker)->worker());
}

void BOB_remote_breakpoint(RemoteWorker *worker) {
	unwrap(worker)->int3();
}

/** \} */

/* -------------------------------------------------------------------- */
/** \name Common Routines
 * \{ */

#ifdef WIN32

#include <windows.h>
#include <tchar.h>

void *BOB_remote_write_manifest(RemoteWorker *worker, const void *vmanifest, size_t size) {
	TCHAR directory[MAX_PATH], filename[MAX_PATH];
	GetTempPath(ARRAYSIZE(directory), directory);
	if (GetTempFileName(directory, _T("ImageManifest"), 0, filename) == 0) {
		return NULL;
	}

	HANDLE fpout = CreateFile(filename, FILE_GENERIC_WRITE, 0, NULL, OPEN_ALWAYS, 0, NULL);
	if (!fpout) {
		return NULL;
	}
	DWORD write;
	if (!WriteFile(fpout, vmanifest, size, &write, NULL)) {
		// return false
	}
	CloseHandle(fpout);

	return BOB_remote_write_ex(worker, filename, sizeof(filename));
}

bool BOB_remote_build_manifest(RemoteWorker *vworker, const void *vmanifest, size_t size) {
	RemoteWorkerImplementation *worker = unwrap(vworker);

	void *manifest = NULL;
	if (!MOM_process_read(worker->host(), worker->ptrmanifest(), &manifest, sizeof(manifest))) {
		return false;
	}

	if (!manifest) {
		ACTCTX context;
		memset(&context, 0, sizeof(ACTCTX));
		context.cbSize = sizeof(ACTCTX);
		context.lpSource = (LPCSTR)BOB_remote_write_manifest(vworker, vmanifest, size);

		ModuleHandle *kernel32 = MOM_process_module_find_by_name(worker->host(), "kernel32.dll");
		ModuleExport *createactctx = MOM_module_export_find_by_name(kernel32, STRINGIFY_DEFINE(CreateActCtx));
		void *_CreateActCtx = MOM_module_export_physical(kernel32, createactctx);

		BOB_remote_begin64(vworker);
		BOB_remote_push_ex(vworker, &context, sizeof(context));
		BOB_remote_call(vworker, kBobWin64, _CreateActCtx);
		BOB_remote_save(vworker, 0);
		BOB_remote_notify(vworker);
		BOB_remote_end64(vworker);

		if (!(manifest = (HANDLE)BOB_remote_exec(vworker, NULL))) {
			return false;
		}

		if (!MOM_process_write(worker->host(), worker->ptrmanifest(), &manifest, sizeof(manifest))) {
			return false;
		}
	}

	return true;
}

bool BOB_remote_bind_manifest(RemoteWorker *vworker) {
	RemoteWorkerImplementation *worker = unwrap(vworker);

	void *manifest = NULL;
	if (!MOM_process_read(worker->host(), worker->ptrmanifest(), &manifest, sizeof(manifest))) {
		return false;
	}

	if (!manifest) {
		return true;
	}

	ModuleHandle *kernel32 = MOM_process_module_find_by_name(worker->host(), "kernel32.dll");
	ModuleExport *activateactctx = MOM_module_export_find_by_name(kernel32, "ActivateActCtx");
	void *_ActivateActCtx = MOM_module_export_physical(kernel32, activateactctx);

	BOB_remote_push(vworker, (uint64_t)manifest, kBobNoDeref);
	BOB_remote_push(vworker, (uint64_t)worker->ptrcookie(), kBobNoDeref);
	BOB_remote_call(vworker, kBobWin64, _ActivateActCtx);
	BOB_remote_save(vworker, 1);

	return true;
}

bool BOB_remote_unbind_manifest(RemoteWorker *vworker) {
	RemoteWorkerImplementation *worker = unwrap(vworker);

	void *manifest = NULL;
	if (!MOM_process_read(worker->host(), worker->ptrmanifest(), &manifest, sizeof(manifest))) {
		return false;
	}

	if (!manifest) {
		return true;
	}

	ModuleHandle *kernel32 = MOM_process_module_find_by_name(worker->host(), "kernel32.dll");
	ModuleExport *deactivateactctx = MOM_module_export_find_by_name(kernel32, "DeactivateActCtx");
	void *_DeactivateActCtx = MOM_module_export_physical(kernel32, deactivateactctx);

	BOB_remote_push(vworker, 0, kBobNoDeref);
	BOB_remote_push(vworker, (uint64_t)worker->ptrcookie(), kBobDeref);
	BOB_remote_call(vworker, kBobWin64, _DeactivateActCtx);
	BOB_remote_save(vworker, 2);

	return true;
}

bool BOB_remote_build_seh(RemoteWorker *vworker, void *real, void *seh, size_t count) {
	RemoteWorkerImplementation *worker = unwrap(vworker);

	ModuleHandle *ntdll = MOM_process_module_find_by_name(worker->host(), "ntdll.dll");
	ModuleExport *rtladdfunctiontable = MOM_module_export_find_by_name(ntdll, "RtlAddFunctionTable");
	void *_RtlAddFunctionTable = MOM_module_export_physical(ntdll, rtladdfunctiontable);

	BOB_remote_begin64(vworker);
	BOB_remote_push(vworker, (uint64_t)real, kBobNoDeref);
	BOB_remote_push(vworker, count, kBobNoDeref);
	BOB_remote_push(vworker, (uint64_t)seh, kBobNoDeref);
	BOB_remote_call(vworker, kBobWin64, _RtlAddFunctionTable);
	BOB_remote_save(vworker, 0);
	BOB_remote_notify(vworker);
	BOB_remote_end64(vworker);

	if (!BOB_remote_exec(vworker, NULL)) {
		return false;
	}

	// fprintf(stdout, "[BOB] 0x%p << RtlAddFunctionTable\n", (void *)BOB_remote_saved(vworker, 0));

	return true;
}

void *BOB_remote_load_dep(RemoteWorker *vworker, ModuleHandle *handle) {
	RemoteWorkerImplementation *worker = unwrap(vworker);

	WCHAR fullpath[MAX_PATH];
	MultiByteToWideChar(CP_ACP, 0, MOM_module_name(handle), -1, fullpath, MAX_PATH);

	ModuleHandle *ntdll = MOM_process_module_find_by_name(worker->host(), "ntdll.dll");
	ModuleExport *rtlinitunicodestring = MOM_module_export_find_by_name(ntdll, "RtlInitUnicodeString");
	ModuleExport *ldrloaddll = MOM_module_export_find_by_name(ntdll, "LdrLoadDll");
	void *_RtlInitUnicodeString = MOM_module_export_physical(ntdll, rtlinitunicodestring);
	void *_LdrLoadDll = MOM_module_export_physical(ntdll, ldrloaddll);

	BOB_remote_begin64(vworker);

	// RtlInitUnicodeString
	void *UnicodeString = BOB_remote_push_ex(vworker, NULL, 0x20);
	BOB_remote_push_wide(vworker, fullpath);
	BOB_remote_call(vworker, kBobWin64, _RtlInitUnicodeString);

	// LdrLoadDll
	BOB_remote_push(vworker, NULL, kBobNoDeref);
	BOB_remote_push(vworker, 0, kBobNoDeref);
	BOB_remote_push(vworker, reinterpret_cast<uint64_t>(UnicodeString), kBobNoDeref);
	void *Module = BOB_remote_push_ex(vworker, NULL, sizeof(HMODULE));
	BOB_remote_call(vworker, kBobWin64, _LdrLoadDll);
	BOB_remote_save(vworker, 0);
	BOB_remote_notify(vworker);

	BOB_remote_end64(vworker);

	if (BOB_remote_exec(vworker, NULL)) {
		return NULL;
	}

	HMODULE module;
	if (!MOM_process_read(worker->host(), Module, &module, sizeof(module))) {
		return NULL;
	}

	return module;
}

bool BOB_remote_call_entry(RemoteWorker *worker, void *real, void *entry) {
	if (!entry) {
		return true;
	}

	BOB_remote_begin64(worker);
	BOB_remote_bind_manifest(worker);
	BOB_remote_push(worker, reinterpret_cast<uint64_t>(real), kBobNoDeref);
	BOB_remote_push(worker, 1, kBobNoDeref); // DLL_PROCESS_ATTACH
	BOB_remote_push(worker, 0, kBobNoDeref);
	BOB_remote_call(worker, kBobWin64, entry);
	BOB_remote_save(worker, 0);
	BOB_remote_unbind_manifest(worker);
	BOB_remote_notify(worker);
	BOB_remote_end64(worker);

	if (!BOB_remote_exec(worker, NULL)) {
		return false;
	}

	return true;
}

#endif

/** \} */
