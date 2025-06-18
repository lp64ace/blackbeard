#include "config.h"
#include "list.h"
#include "module.h"
#include "native.h"
#include "process.h"
#include "thread.h"
#include "remote.h"

#define ASMJIT_STATIC
#include "core.h"
#include "x86.h"
#include "a64.h"

#include <new>

/* -------------------------------------------------------------------- */
/** \name Internal
 * \{ */

class BobRemoteImplementation {
	struct Header {
		uint64_t saved[8];
	};
	
	struct Param {
		struct Param *prev, *next;
		
		uint64_t imm;
		int ref; // More like deref but I like to keep names equal-length!
	};
	
protected:
	void begin_call64(asmjit::x86::Assembler &ASM) {
		ASM.sub(asmjit::x86::rsp, asmjit::imm(0x28));

		ASM.mov(asmjit::x86::qword_ptr(asmjit::x86::rsp, 0x8), asmjit::x86::rcx); // MOV [RSP + 0x08], RCX
		ASM.mov(asmjit::x86::qword_ptr(asmjit::x86::rsp, 0x10), asmjit::x86::rdx); // MOV [RSP + 0x10], RDX
		ASM.mov(asmjit::x86::qword_ptr(asmjit::x86::rsp, 0x18), asmjit::x86::r8); // MOV [RSP + 0x18], R8
		ASM.mov(asmjit::x86::qword_ptr(asmjit::x86::rsp, 0x20), asmjit::x86::r9); // MOV [RSP + 0x20], R9
	}
	
	void end_call64(asmjit::x86::Assembler &ASM) {
		ASM.mov(asmjit::x86::rcx, asmjit::x86::qword_ptr(asmjit::x86::rsp, 0x08)); // MOV RCX, QWORD PTR [RSP + 0x08]
		ASM.mov(asmjit::x86::rdx, asmjit::x86::qword_ptr(asmjit::x86::rsp, 0x10)); // MOV RDX, QWORD PTR [RSP + 0x10]
		ASM.mov(asmjit::x86::r8, asmjit::x86::qword_ptr(asmjit::x86::rsp, 0x18)); // MOV R8 , QWORD PTR [RSP + 0x18]
		ASM.mov(asmjit::x86::r9, asmjit::x86::qword_ptr(asmjit::x86::rsp, 0x20)); // MOV R9 , QWORD PTR [RSP + 0x20]
	
		ASM.add(asmjit::x86::rsp, asmjit::imm(0x28));
		ASM.ret();
	}
	
	void store(asmjit::x86::Assembler &ASM, const asmjit::x86::Gp &reg, Param *param) {
		switch (param->ref) {
			case DEREFPTR: {
				if (ASM.is64Bit()) {
					ASM.mov(asmjit::x86::rax, asmjit::imm(param->imm));
					ASM.mov(reg, asmjit::x86::qword_ptr(asmjit::x86::rax));
				} else {
					ASM.mov(asmjit::x86::eax, asmjit::imm(param->imm));
					ASM.mov(reg, asmjit::x86::dword_ptr(asmjit::x86::eax));
				}
			} break;
			case DEREFIMM32: {
				if (ASM.is64Bit()) {
					ASM.mov(asmjit::x86::rax, asmjit::imm(param->imm));
					ASM.mov(reg, asmjit::x86::dword_ptr(asmjit::x86::rax));
				} else {
					ASM.mov(asmjit::x86::eax, asmjit::imm(param->imm));
					ASM.mov(reg, asmjit::x86::dword_ptr(asmjit::x86::eax));
				}
			} break;
			case DEREFIMM64: {
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
	
	void push(asmjit::x86::Assembler &ASM, Param *param) {
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
			if ((p = static_cast<Param *>(LIB_pophead(&this->params)))) {  // RCX
				store(ASM, asmjit::x86::rcx, p);
				bobFree(p);
			}
			if ((p = static_cast<Param *>(LIB_pophead(&this->params)))) {  // RDX
				store(ASM, asmjit::x86::rdx, p);
				bobFree(p);
			}
			if ((p = static_cast<Param *>(LIB_pophead(&this->params)))) {  // R8
				store(ASM, asmjit::x86::r8, p);
				bobFree(p);
			}
			if ((p = static_cast<Param *>(LIB_pophead(&this->params)))) {  // R9
				store(ASM, asmjit::x86::r9, p);
				bobFree(p);
			}
			
			while ((p = static_cast<Param *>(LIB_poptail(&this->params)))) {
				push(ASM, p);
				bobFree(p);
			}
			
			ASM.mov(asmjit::x86::r13, asmjit::imm(procedure));
			ASM.call(asmjit::x86::r13);
			ASM.add(asmjit::x86::rsp, asmjit::imm(diff)); // ADD RSP, diff
		} else {
			if (nparams < 2) {
				Param *p = static_cast<Param *>(this->params.first);
				if ((p = static_cast<Param *>(LIB_pophead(&this->params)))) {  // EDX
					store(ASM, asmjit::x86::edx, p);
					bobFree(p);
				}

				stdcall(ASM, procedure);
			}

			Param *p = static_cast<Param *>(this->params.first);
			if ((p = static_cast<Param *>(LIB_pophead(&this->params)))) {  // EDX
				store(ASM, asmjit::x86::edx, p);
				bobFree(p);
			}
			if ((p = static_cast<Param *>(LIB_pophead(&this->params)))) {  // EAX
				store(ASM, asmjit::x86::eax, p);
				bobFree(p);
			}

			while ((p = static_cast<Param *>(LIB_poptail(&this->params)))) {
				push(ASM, p);
				bobFree(p);
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
			bobFree(p);
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
		if ((p = static_cast<Param *>(LIB_pophead(&this->params)))) {  // ECX
			store(ASM, asmjit::x86::ecx, p);
			bobFree(p);
		}

		while ((p = static_cast<Param *>(LIB_poptail(&this->params)))) {
			push(ASM, p);
			bobFree(p);
		}

		ASM.mov(asmjit::x86::eax, asmjit::imm(procedure));
		ASM.call(asmjit::x86::eax);

		LIB_listbase_clear(&this->params);
	}
	
public:
	BobRemoteImplementation(BobProcess *process, bool x64 = true) : process(process), asmruntime(), codeholder(), thread(NULL) {
		if (x64) {
			this->codeholder.init(asmjit::Environment(asmjit::Arch::kX64), asmruntime.cpuFeatures());
		}
		else {
			this->codeholder.init(asmjit::Environment(asmjit::Arch::kX86), asmruntime.cpuFeatures());
		}
		
		this->loop = BOB_process_alloc(process, NULL, 0x1000, PROTECT_R | PROTECT_W | PROTECT_E); // 4KB
		this->code = BOB_process_alloc(process, NULL, 0x1000, PROTECT_R | PROTECT_W | PROTECT_E); // 4KB
		this->user = BOB_process_alloc(process, NULL, 0x400000, PROTECT_R | PROTECT_W); // 4MB
		this->offset = sizeof(Header);

		LIB_listbase_clear(&this->params);
	}
	
	~BobRemoteImplementation() {
		BOB_thread_terminate(this->thread, 0);
		BOB_thread_close(this->thread);

		BOB_process_free(process, this->loop, 0);
		BOB_process_free(process, this->code, 0);
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

	void push(uint64_t imm, int ref) {
		Param *p = static_cast<Param *>(bobAlloc(sizeof(Param)));
		
		p->imm = imm;
		p->ref = ref;
		
		LIB_addtail(&this->params, p);
	}
	
	void *write(const void *buffer, size_t size) {
		void *address = POINTER_OFFSET(this->user, this->offset);
		if (buffer) {
			BOB_process_write(this->process, address, buffer, size);
		}
		this->offset = this->offset + size;
		return address;
	}
	
	bool init() {
		// !CAUTION! Different codeholder within this context for important reasons!
		asmjit::CodeHolder codeholder;
		codeholder.init(this->codeholder.environment(), this->asmruntime.cpuFeatures());
		
		this->evtlocal = bobCreateEventW(NULL, TRUE, FALSE, NULL);
		if (!bobDuplicateHandle(GetCurrentProcess(), this->evtlocal, this->process, &this->evtremote, 0, FALSE, DUPLICATE_SAME_ACCESS)) {
			return false;
		}
		
		BobModule *kernel32 = BOB_module_open_by_name(process, "kernel32.dll", SEARCH_DEFAULT);
		
		asmjit::x86::Assembler ASM(&codeholder);
		
		if (ASM.is64Bit()) {
			begin_call64(ASM);
		}
		
		asmjit::Label loop = ASM.newLabel();
		ASM.bind(loop);
		{
			push(0x05, NODEREF);
			push(TRUE, NODEREF);
			call(ASM, BOB_module_export(process, kernel32, "SleepEx"));
		}
		ASM.jmp(loop);
		
		if (ASM.is64Bit()) {
			end_call64(ASM);
		}
		
		asmjit::Section *section = codeholder.sectionById(0);
		asmjit::CodeBuffer buffer = section->buffer();
		
		if (!BOB_process_write(this->process, this->loop, buffer.data(), buffer.size())) {
			return false;
		}

		this->thread = BOB_thread_new(this->process, this->loop, NULL);
		
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
				if (!BOB_process_write(this->process, this->code, buffer.data(), buffer.size())) {
					return NULL;
				}
			}
		}
		
		this->codeholder.reset(asmjit::ResetPolicy::kHard);
		this->codeholder.init(this->asmruntime.environment(), this->asmruntime.cpuFeatures());
		
		return this->code;
	}
	
	BobProcess *host() const {
		return this->process;
	}

	BobThread *worker() const {
		return this->thread;
	}

	void *ptrsave(size_t index) const {
		return POINTER_OFFSET(this->user, offsetof(Header, saved[index]));
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
		}
		else {
			ASM.mov(asmjit::x86::edx, asmjit::imm(reinterpret_cast<uint32_t>(ret)));
			ASM.mov(asmjit::x86::dword_ptr(asmjit::x86::edx), asmjit::x86::eax);
		}
	}
	
	void notify() {
		asmjit::x86::Assembler ASM(&this->codeholder);

		BobModule *kernel32 = BOB_module_open_by_name(this->process, "kernel32.dll", SEARCH_DEFAULT);

		if (ASM.is64Bit()) {
			void *SetEvent = BOB_module_export(this->process, kernel32, "SetEvent");
			ASM.mov(asmjit::x86::rcx, asmjit::imm(this->evtremote));    // rcx = HANDLE
			ASM.mov(asmjit::x86::rax, asmjit::imm((uint64_t)SetEvent)); // rax = &SetEvent
			ASM.call(asmjit::x86::rax);                                 // call SetEvent(rcx)
		} else {
			// On x86, SetEvent uses stdcall: push HANDLE, then call
			void *SetEvent = BOB_module_export(this->process, kernel32, "SetEvent");
			ASM.push(asmjit::imm(this->evtremote));                     // push HANDLE
			ASM.mov(asmjit::x86::eax, asmjit::imm((uint32_t)SetEvent)); // eax = &SetEvent
			ASM.call(asmjit::x86::eax);                                 // call SetEvent
		}
	}
	
	uint64_t invoke(void *argument) {
		void *code;
		if ((code = this->make())) {
			QueueUserAPC(reinterpret_cast<PAPCFUNC>(code), reinterpret_cast<HANDLE>(thread), reinterpret_cast<ULONG_PTR>(argument));
			if (WaitForSingleObject(evtlocal, INFINITE) != WAIT_OBJECT_0) {
				// return 0;
			}
			ResetEvent(evtlocal);
			
			uint64_t ret;
			BOB_process_read(this->process, this->ptrsave(0), &ret, sizeof(ret));
			return ret;
		}
		return 0;
	}
	
private:
	BobProcess *process;
	BobThread *thread;
	
	asmjit::JitRuntime asmruntime;
	asmjit::CodeHolder codeholder;
	
	HANDLE evtlocal = INVALID_HANDLE_VALUE;
	HANDLE evtremote = INVALID_HANDLE_VALUE;
	
	void *loop;
	void *code;
	void *user;
	
	size_t offset;
	
	ListBase params;
};

BobRemote *wrap(class BobRemoteImplementation *self) {
	return reinterpret_cast<BobRemote *>(self);
}
const BobRemote *wrap(const class BobRemoteImplementation *self) {
	return reinterpret_cast<const BobRemote *>(self);
}

BobRemoteImplementation *unwrap(struct BobRemote *self) {
	return reinterpret_cast<BobRemoteImplementation *>(self);
}
const BobRemoteImplementation *unwrap(const struct BobRemote *self) {
	return reinterpret_cast<const BobRemoteImplementation *>(self);
}

/** \} */

/* -------------------------------------------------------------------- */
/** \name Implementations
 * \{ */

BobRemote *BOB_remote_open(BobProcess *process) {
	BobRemoteImplementation *self = static_cast<BobRemoteImplementation *>(bobAlloc(sizeof(BobRemoteImplementation)));
	self = new (self) BobRemoteImplementation(process);
	if (!self->init()) {
		BOB_remote_close(wrap(self));
		self = nullptr;
	}
	return wrap(self);
}

void BOB_remote_close(BobRemote *remote) {
	unwrap(remote)->~BobRemoteImplementation();
	bobFree(remote);
}

/** \} */

/* -------------------------------------------------------------------- */
/** \name Remote Execution
 * \{ */

void BOB_remote_breakpoint(struct BobRemote *remote) {
	unwrap(remote)->int3();
}

void BOB_remote_push(BobRemote *remote, const uint64_t imm, int deref) {
	unwrap(remote)->push(imm, deref);
}

void *BOB_remote_write(BobRemote *remote, const void *buffer, size_t length) {
	return unwrap(remote)->write(buffer, length);
}

void *BOB_remote_push_ex(BobRemote *remote, const void *buffer, size_t length) {
	void *address = BOB_remote_write(remote, buffer, length);
	BOB_remote_push(remote, reinterpret_cast<uint64_t>(address), NODEREF);
	return address;
}

void *BOB_remote_push_ansi(BobRemote *remote, const char *ansi) {
	return BOB_remote_push_ex(remote, ansi, sizeof(char) * (strlen(ansi) + 1));
}

void *BOB_remote_push_wide(BobRemote *remote, const wchar_t *wide) {
	return BOB_remote_push_ex(remote, wide, sizeof(wchar_t) * (wcslen(wide) + 1));
}

void BOB_remote_begin64(BobRemote *remote) {
	unwrap(remote)->begin_call64();
}

void BOB_remote_call(BobRemote *remote, const void *procedure) {
	unwrap(remote)->call(procedure);
}

void BOB_remote_fastcall(BobRemote *remote, const void *procedure) {
	unwrap(remote)->fastcall(procedure);
}

void BOB_remote_thiscall(BobRemote *remote, const void *procedure) {
	unwrap(remote)->thiscall(procedure);
}

void BOB_remote_save(BobRemote *remote, size_t index) {
	unwrap(remote)->save(index);
}

void BOB_remote_end64(BobRemote *remote) {
	unwrap(remote)->end_call64();
}

void BOB_remote_notify(BobRemote *remote) {
	unwrap(remote)->notify();
}

uint64_t BOB_remote_invoke(BobRemote *remote, void *argument) {
	return unwrap(remote)->invoke(argument);
}

/** \} */

/* -------------------------------------------------------------------- */
/** \name Queries
 * \{ */

uint64_t BOB_remote_saved(const BobRemote *remote, size_t index) {
	uint64_t ret;

	void *ptr = unwrap(remote)->ptrsave(index);
	BOB_process_read(unwrap(remote)->host(), ptr, &ret, sizeof(ret));
	return ret;
}

BobThread *BOB_remote_thread(const BobRemote *remote) {
	return unwrap(remote)->worker();
}

/** \} */
