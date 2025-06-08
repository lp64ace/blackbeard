#include "config.h"
#include "list.h"
#include "mod.h"
#include "native.h"
#include "remote.h"
#include "spoof.h"
#include "thread.h"
#include "proc.h"

#include "xorstr.hh"

#include "asm/core.h"
#include "asm/x86.h"
#include "asm/a64.h"

#include <assert.h>
#include <sddl.h>
#include <tchar.h>

#include <vector>

/* -------------------------------------------------------------------- */
/** \name Impl
 * \{ */

enum {
	CODE,
	LOOP,
};

struct BobRemote {
	BobProc *process = NULL;

	/** Prefix for #BobRemote->data, that stores internal data */
	struct Internal {
		uint64_t ret[8];  // User requested return value save!
		uint64_t evt;  // Event handle for the remote thread to signal completion
	};

	void *code = NULL;
	void *loop = NULL;
	void *data = NULL;
	size_t offset = sizeof(Internal);

	asmjit::JitRuntime runtime;
	asmjit::CodeHolder holder;
	BobThread *thread = NULL;

	ListBase params;

	TCHAR apc[256] = _T("");
	HANDLE event = INVALID_HANDLE_VALUE;

	BobRemote(bool x64) : runtime() {
		if (x64) {
			holder.init(asmjit::Environment(asmjit::Arch::kX64), runtime.cpuFeatures());
		}
		else {
			holder.init(asmjit::Environment(asmjit::Arch::kX86), runtime.cpuFeatures());
		}

		LIB_listbase_clear(&params);
	}
};

struct BobRemoteParam {
	struct BobRemoteParam *prev, *next;
	
	int type;
	asmjit::Imm imm;
};

enum {
	IMM,  // immediate value
	REF,
	REF4,  // reference to memory
	REF8,  // reference to memory
};

// backup param registers
void bob_remote_begin_call64(asmjit::x86::Assembler &ASM) {
	ASM.sub(asmjit::x86::rsp, 0x28);

	// MOV [RSP + 0x08], RCX
	ASM.mov(asmjit::x86::qword_ptr(asmjit::x86::rsp, 0x8), asmjit::x86::rcx);
	// MOV [RSP + 0x10], RDX
	ASM.mov(asmjit::x86::qword_ptr(asmjit::x86::rsp, 0x10), asmjit::x86::rdx);
	// MOV [RSP + 0x18], R8
	ASM.mov(asmjit::x86::qword_ptr(asmjit::x86::rsp, 0x18), asmjit::x86::r8);
	// MOV [RSP + 0x20], R9
	ASM.mov(asmjit::x86::qword_ptr(asmjit::x86::rsp, 0x20), asmjit::x86::r9);
}

BOB_STATIC void bob_remote_store(asmjit::x86::Assembler &ASM, struct BobRemoteParam *param, const asmjit::x86::Gp &reg) {
	assert(reg != asmjit::x86::rax);
	assert(reg != asmjit::x86::eax);

	switch (param->type) {
		case REF: {	 // size
			if (ASM.is64Bit()) {
				ASM.mov(asmjit::x86::rax, param->imm);
				ASM.mov(reg, asmjit::x86::qword_ptr(asmjit::x86::rax));
			}
			else {
				ASM.mov(asmjit::x86::eax, param->imm);
				ASM.mov(reg, asmjit::x86::dword_ptr(asmjit::x86::eax));
			}
		} break;
		case REF4: {  // int32
			if (ASM.is64Bit()) {
				ASM.mov(asmjit::x86::rax, param->imm);
				ASM.mov(reg, asmjit::x86::dword_ptr(asmjit::x86::rax));
			}
			else {
				ASM.mov(asmjit::x86::eax, param->imm);
				ASM.mov(reg, asmjit::x86::dword_ptr(asmjit::x86::eax));
			}
		} break;
		case REF8: {  // int64
			if (ASM.is64Bit()) {
				ASM.mov(asmjit::x86::rax, param->imm);
				ASM.mov(reg, asmjit::x86::qword_ptr(asmjit::x86::rax));
			}
			else {
				assert(0);
				// ASM.mov(asmjit::x86::eax, param->imm);
				// ASM.mov(reg, asmjit::x86::qword_ptr(asmjit::x86::eax));
			}
		} break;
		default: {
			ASM.mov(reg, param->imm);
		} break;
	}
}

BOB_STATIC void bob_remote_push(asmjit::x86::Assembler &ASM, struct BobRemoteParam *param) {
	if (ASM.is64Bit()) {
		bob_remote_store(ASM, param, asmjit::x86::rbx);
		ASM.push(asmjit::x86::rbx);
	}
	else {
		bob_remote_store(ASM, param, asmjit::x86::ebx);
		ASM.push(asmjit::x86::ebx);
	}
}

void bob_remote_call(BobRemote *remote, asmjit::x86::Assembler &ASM, int convention, const void *proc) {
	size_t nparam = LIB_listbase_count(&remote->params);
	if ((ASM.is64Bit() || convention == REMOTE_WIN64) || convention == REMOTE_FASTCALL) {
		if (ASM.is64Bit()) {
			size_t rsp_dif = (nparam > 4) ? (1 + nparam) * sizeof(size_t) : 0x28;
			rsp_dif = (rsp_dif + 0x10) & ~0xF;	// align to 16 bytes

			// SUB RSP, rsp_dif
			ASM.sub(asmjit::x86::rsp, rsp_dif);

			BobRemoteParam *p = static_cast<BobRemoteParam *>(remote->params.first);
			if ((p = static_cast<BobRemoteParam *>(LIB_pophead(&remote->params)))) {  // RCX
				bob_remote_store(ASM, p, asmjit::x86::rcx);
				BOB_FREE(p);
			}
			if ((p = static_cast<BobRemoteParam *>(LIB_pophead(&remote->params)))) {  // RDX
				bob_remote_store(ASM, p, asmjit::x86::rdx);
				BOB_FREE(p);
			}
			if ((p = static_cast<BobRemoteParam *>(LIB_pophead(&remote->params)))) {  // R8
				bob_remote_store(ASM, p, asmjit::x86::r8);
				BOB_FREE(p);
			}
			if ((p = static_cast<BobRemoteParam *>(LIB_pophead(&remote->params)))) {  // R9
				bob_remote_store(ASM, p, asmjit::x86::r9);
				BOB_FREE(p);
			}

			while ((p = static_cast<BobRemoteParam *>(LIB_poptail(&remote->params)))) {
				bob_remote_push(ASM, p);
				BOB_FREE(p);
			}

			ASM.mov(asmjit::x86::r13, proc);
			ASM.call(asmjit::x86::r13);

			// ADD RSP, rsp_dif
			ASM.add(asmjit::x86::rsp, rsp_dif);
		}
		else {
			if (nparam < 2) {
				BobRemoteParam *p = static_cast<BobRemoteParam *>(remote->params.first);
				if ((p = static_cast<BobRemoteParam *>(LIB_pophead(&remote->params)))) {  // EDX
					bob_remote_store(ASM, p, asmjit::x86::edx);
					BOB_FREE(p);
				}

				return bob_remote_call(remote, ASM, REMOTE_STDCALL, proc);
			}

			BobRemoteParam *p = static_cast<BobRemoteParam *>(remote->params.first);
			if ((p = static_cast<BobRemoteParam *>(LIB_pophead(&remote->params)))) {  // EDX
				bob_remote_store(ASM, p, asmjit::x86::edx);
				BOB_FREE(p);
			}
			if ((p = static_cast<BobRemoteParam *>(LIB_pophead(&remote->params)))) {  // EAX
				bob_remote_store(ASM, p, asmjit::x86::eax);
				BOB_FREE(p);
			}

			while ((p = static_cast<BobRemoteParam *>(LIB_poptail(&remote->params)))) {
				bob_remote_push(ASM, p);
				BOB_FREE(p);
			}

			ASM.mov(asmjit::x86::ebx, proc);
			ASM.call(asmjit::x86::ebx);
		}
	}
	else if (convention == REMOTE_CDECL) {
		size_t size = sizeof(uintptr_t) * nparam;

		BobRemoteParam *p;
		while ((p = static_cast<BobRemoteParam *>(LIB_poptail(&remote->params)))) {
			bob_remote_push(ASM, p);
			BOB_FREE(p);
		}

		ASM.mov(asmjit::x86::eax, proc);
		ASM.call(asmjit::x86::eax);

		if (size) {
			ASM.add(asmjit::x86::esp, size);
		}
	}
	else if (convention == REMOTE_STDCALL) {
		BobRemoteParam *p;
		while ((p = static_cast<BobRemoteParam *>(LIB_poptail(&remote->params)))) {
			bob_remote_push(ASM, p);
			BOB_FREE(p);
		}

		ASM.mov(asmjit::x86::eax, proc);
		ASM.call(asmjit::x86::eax);
	}
	else if (convention == REMOTE_THISCALL) {
		BobRemoteParam *p = static_cast<BobRemoteParam *>(remote->params.first);
		if ((p = static_cast<BobRemoteParam *>(LIB_pophead(&remote->params)))) {  // ECX
			bob_remote_store(ASM, p, asmjit::x86::ecx);
			BOB_FREE(p);
		}

		while ((p = static_cast<BobRemoteParam *>(LIB_poptail(&remote->params)))) {
			bob_remote_push(ASM, p);
			BOB_FREE(p);
		}

		ASM.mov(asmjit::x86::eax, proc);
		ASM.call(asmjit::x86::eax);
	}
}

// Restore registers and return
void bob_remote_end_call64(asmjit::x86::Assembler &ASM) {
	// MOV RCX, QWORD PTR [RSP + 0x08]
	ASM.mov(asmjit::x86::rcx, asmjit::x86::qword_ptr(asmjit::x86::rsp, 0x08));
	// MOV RDX, QWORD PTR [RSP + 0x10]
	ASM.mov(asmjit::x86::rdx, asmjit::x86::qword_ptr(asmjit::x86::rsp, 0x10));
	// MOV R8 , QWORD PTR [RSP + 0x18]
	ASM.mov(asmjit::x86::r8, asmjit::x86::qword_ptr(asmjit::x86::rsp, 0x18));
	// MOV R9 , QWORD PTR [RSP + 0x20]
	ASM.mov(asmjit::x86::r9, asmjit::x86::qword_ptr(asmjit::x86::rsp, 0x20));

	ASM.add(asmjit::x86::rsp, 0x28);

	ASM.ret();
}

BOB_STATIC bool bob_remote_read(struct BobRemote *remote, BobRemote::Internal *in) {
	bool status = true;
	if (!BOB_process_read(remote->process, POINTER_OFFSET(remote->data, offsetof(BobRemote::Internal, ret)), &in->ret, sizeof(in->ret))) {
		status &= false;
	}
	if (!BOB_process_read(remote->process, POINTER_OFFSET(remote->data, offsetof(BobRemote::Internal, evt)), &in->evt, sizeof(in->evt))) {
		status &= false;
	}
	return status;
}

BOB_STATIC bool bob_remote_write(struct BobRemote *remote, BobRemote::Internal *in) {
	return true;
}

BOB_STATIC bool bob_remote_build(struct BobRemote *remote) {
	bool status = true;

	// We could update this so that we can write multiple sections at once, but for now we just write the first section.
	assert(0 < remote->holder.sectionCount() && remote->holder.sectionCount() <= 1);
	for (size_t index = 0; index < remote->holder.sectionCount(); index++) {
		asmjit::Section *section = remote->holder.sectionById(index);
		if (section) {
			asmjit::CodeBuffer buffer = section->buffer();

			BOB_DEBUG_PRINT(stdout, XORSTR("0x%p | "), POINTER_OFFSET(remote->code, 0));
			for (size_t byte = 0; byte < buffer.size(); byte++) {
				if (byte && byte % 8 == 0) {
					BOB_DEBUG_PRINT(stdout, XORSTR("\n"));
					BOB_DEBUG_PRINT(stdout, XORSTR("0x%p | "), POINTER_OFFSET(remote->code, byte));
				}
				BOB_DEBUG_PRINT(stdout, XORSTR("%02x "), buffer[byte]);
			}
			BOB_DEBUG_PRINT(stdout, XORSTR("\n"));

			if (!BOB_process_write(remote->process, remote->code, buffer.data(), buffer.size())) {
				status &= false;
			}
		}

	}

	remote->holder.reset(asmjit::ResetPolicy::kHard);
	remote->holder.init(remote->runtime.environment(), remote->runtime.cpuFeatures());

	return status;
}

BOB_STATIC bool bob_remote_apc(struct BobRemote *remote) {
	if (remote->event && remote->event != INVALID_HANDLE_VALUE) {
		return true;
	}

	asmjit::JitRuntime runtime;
	asmjit::CodeHolder holder;
	holder.init(runtime.environment(), runtime.cpuFeatures());

	asmjit::x86::Assembler ASM(&holder);
	_sntprintf(remote->apc, ARRAYSIZE(remote->apc), XORSTR("_Bob_0x%x_"), (int)GetTickCount());

	BobModule *kernel32 = BOB_module_open(remote->process, XORSTR("kernel32.dll"), SEARCH_DEFAULT);
	decltype(&CreateEvent) _CreateEvent = static_cast<decltype(&CreateEvent)>(BOB_module_export(remote->process, kernel32, XORSTR(STRINGIFY_DEFINE(CreateEvent))));

	void *evt = POINTER_OFFSET(remote->data, offsetof(BobRemote::Internal, evt));
	if (ASM.is64Bit()) {
		bob_remote_begin_call64(ASM);

		BOB_remote_push_ptr(remote, NULL);	// lpEventAttributes
		BOB_remote_push_int(remote, 1);		// bManualReset
		BOB_remote_push_int(remote, 0);		// bInitialState
		BOB_remote_push(remote, remote->apc, sizeof(remote->apc));
		bob_remote_call(remote, ASM, REMOTE_WIN64, _CreateEvent);

		ASM.mov(asmjit::x86::rdx, (uint64_t)evt);
		ASM.mov(asmjit::x86::qword_ptr(asmjit::x86::rdx), asmjit::x86::rax);

		bob_remote_end_call64(ASM);

		asmjit::Section *section = holder.sectionById(0);

		if (section) {
			void *ptr = BOB_process_alloc(remote->process, NULL, 0x1000, PROTECT_R | PROTECT_W | PROTECT_E);
			BOB_process_write(remote->process, ptr, section->buffer().data(), section->buffer().size());
			BobThread *thread = BOB_thread_new(remote->process, ptr, NULL);
			BOB_thread_join(thread);
			BOB_thread_close(thread);
			BOB_process_free(remote->process, ptr);
		}

		BobRemote::Internal internal;
		if (!bob_remote_read(remote, &internal)) {
			return false;
		}
		if (!internal.evt) {
			return false;
		}
		remote->event = reinterpret_cast<HANDLE>(OpenEvent(EVENT_MODIFY_STATE | SYNCHRONIZE, FALSE, remote->apc));
	}

	return true;
}

BOB_STATIC BobRemote *bob_remote_new(struct BobProc *process, bool x64) {
	BobRemote *remote = static_cast<BobRemote *>(BOB_ALLOC(sizeof(BobRemote)));
	remote = new (remote) BobRemote(x64);

	remote->process = process;
	remote->code = BOB_process_alloc(remote->process, NULL, 0x1000, PROTECT_R | PROTECT_W | PROTECT_E);
	remote->loop = BOB_process_alloc(remote->process, NULL, 0x1000, PROTECT_R | PROTECT_W | PROTECT_E);
	remote->data = BOB_process_alloc(remote->process, NULL, 0x1000, PROTECT_R | PROTECT_W);

	if (x64) {
		bob_remote_apc(remote);
	}

	return remote;
}

BOB_STATIC void bob_remote_free(struct BobRemote *remote) {
	LISTBASE_FOREACH_MUTABLE(BobRemoteParam *, param, &remote->params) {
		LIB_remlink(&remote->params, param);
		BOB_FREE(param);
	}
	BOB_process_free(remote->process, remote->data);
	BOB_process_free(remote->process, remote->code);
	BOB_process_free(remote->process, remote->loop);
	CloseHandle(remote->event);
	if (remote->thread) {
		BOB_thread_terminate(remote->thread);
		BOB_thread_close(remote->thread);
		remote->thread = NULL;
	}
	remote->~BobRemote();
}

BobRemote *BOB_remote_open(struct BobProc *process, bool x64) {
	BobRemote *remote = bob_remote_new(process, x64);

	BobModule *kernel32 = BOB_module_open(process, XORSTR("kernel32.dll"), SEARCH_DEFAULT);
	decltype(&SleepEx) _SleepEx = static_cast<decltype(&SleepEx)>(BOB_module_export(process, kernel32, XORSTR("SleepEx")));

	asmjit::JitRuntime runtime;
	asmjit::CodeHolder holder;
	holder.init(runtime.environment(), runtime.cpuFeatures());

	asmjit::x86::Assembler ASM(&holder);

	/*
		for (;;) {
			SleepEx(5, TRUE);
		}
		ExitThread(SetEvent(m_hWaitEvent));
	*/

	bob_remote_begin_call64(ASM);

	asmjit::Label loop = ASM.newLabel();
	ASM.bind(loop);
	{
		BOB_remote_push_int(remote, 5);
		BOB_remote_push_int(remote, TRUE);
		bob_remote_call(remote, ASM, REMOTE_STDCALL, _SleepEx);
	}
	ASM.jmp(loop);

	bob_remote_end_call64(ASM);

	asmjit::Section *section = holder.sectionById(0);
	if (section) {
		BOB_process_write(remote->process, remote->loop, section->buffer().data(), section->buffer().size());
		remote->thread = BOB_thread_new(remote->process, remote->loop, NULL);
	}

	return remote;
}

void BOB_remote_close(struct BobRemote *remote) {
	bob_remote_free(remote);
	BOB_FREE(remote);
}

void *BOB_remote_write(struct BobRemote *remote, const void *data, size_t size) {
	void *addr = POINTER_OFFSET(remote->data, remote->offset);
	if (data) {
		BOB_process_write(remote->process, addr, data, size);
	}
	remote->offset += size;
	return addr;
}
void *BOB_remote_push(struct BobRemote *remote, const void *data, size_t size) {
	void *addr = BOB_remote_write(remote, data, size);
	BOB_remote_push_ptr(remote, addr);
	return addr;
}
void BOB_remote_push_int(struct BobRemote *remote, int arg) {
	BobRemoteParam *param = static_cast<BobRemoteParam *>(BOB_ALLOC(sizeof(BobRemoteParam)));
	param = new (param) BobRemoteParam();
	param->imm = asmjit::Imm(arg);
	param->type = IMM;
	LIB_addtail(&remote->params, param);
}
void BOB_remote_push_ptr(struct BobRemote *remote, const void *arg) {
	BobRemoteParam *param = static_cast<BobRemoteParam *>(BOB_ALLOC(sizeof(BobRemoteParam)));
	param = new (param) BobRemoteParam();
	param->imm = asmjit::Imm(arg);
	param->type = IMM;
	LIB_addtail(&remote->params, param);
}
void *BOB_remote_push_str(struct BobRemote *remote, const char *arg) {
	return BOB_remote_push(remote, arg, sizeof(char) * (strlen(arg) + 1));
}
void *BOB_remote_push_wstr(struct BobRemote *remote, const wchar_t *arg) {
	return BOB_remote_push(remote, arg, sizeof(wchar_t) * (wcslen(arg) + 1));
}
void BOB_remote_push_ref(struct BobRemote *remote, const void *arg) {
	BobRemoteParam *param = static_cast<BobRemoteParam *>(BOB_ALLOC(sizeof(BobRemoteParam)));
	param = new (param) BobRemoteParam();
	param->imm = asmjit::Imm(arg);
	param->type = REF;
	LIB_addtail(&remote->params, param);
}
void BOB_remote_push_ref4(struct BobRemote *remote, const void *arg) {
	BobRemoteParam *param = static_cast<BobRemoteParam *>(BOB_ALLOC(sizeof(BobRemoteParam)));
	param = new (param) BobRemoteParam();
	param->imm = asmjit::Imm(arg);
	param->type = REF4;
	LIB_addtail(&remote->params, param);
}
void BOB_remote_push_ref8(struct BobRemote *remote, const void *arg) {
	BobRemoteParam *param = static_cast<BobRemoteParam *>(BOB_ALLOC(sizeof(BobRemoteParam)));
	param = new (param) BobRemoteParam();
	param->imm = asmjit::Imm(arg);
	param->type = REF8;
	LIB_addtail(&remote->params, param);
}

void BOB_remote_notify(struct BobRemote *remote) {
	asmjit::x86::Assembler ASM(&remote->holder);

	BobModule *kernel32 = BOB_module_open(remote->process, XORSTR("kernel32.dll"), SEARCH_DEFAULT);
	decltype(&SetEvent) _SetEvent = static_cast<decltype(&SetEvent)>(BOB_module_export(remote->process, kernel32, XORSTR("SetEvent")));

	void *evt = POINTER_OFFSET(remote->data, offsetof(BobRemote::Internal, evt));
	if (ASM.is64Bit()) {
		// Load pointer to remote->Internal.evt, then load its value (the HANDLE) into RCX
		ASM.mov(asmjit::x86::rcx, (uint64_t)evt);							  // rcx = &remote->evt
		ASM.mov(asmjit::x86::rcx, asmjit::x86::qword_ptr(asmjit::x86::rcx));  // rcx = *rcx (the HANDLE)
		ASM.mov(asmjit::x86::rax, (uint64_t)_SetEvent);						  // rax = &SetEvent
		ASM.call(asmjit::x86::rax);											  // call SetEvent(rcx)
	}
	else {
		// On x86, SetEvent uses stdcall: push HANDLE, then call
		ASM.mov(asmjit::x86::eax, (uint32_t)(uintptr_t)evt);				  // eax = &remote->evt
		ASM.mov(asmjit::x86::eax, asmjit::x86::dword_ptr(asmjit::x86::eax));  // eax = *eax (HANDLE)
		ASM.push(asmjit::x86::eax);											  // push HANDLE
		ASM.mov(asmjit::x86::eax, (uint32_t)(uintptr_t)_SetEvent);			  // eax = &SetEvent
		ASM.call(asmjit::x86::eax);											  // call SetEvent
	}
}

void BOB_remote_begin_call64(struct BobRemote *remote) {
	asmjit::x86::Assembler ASM(&remote->holder);

	bob_remote_begin_call64(ASM);
}

void BOB_remote_call(struct BobRemote *remote, int convention, const void *proc) {
	asmjit::x86::Assembler ASM(&remote->holder);

	bob_remote_call(remote, ASM, convention, proc);
}

void BOB_remote_end_call64(struct BobRemote *remote) {
	asmjit::x86::Assembler ASM(&remote->holder);

	bob_remote_end_call64(ASM);
}

void BOB_remote_save(struct BobRemote *remote, int at) {
	asmjit::x86::Assembler ASM(&remote->holder);

	/**
	 * Write the current return value into internal data.
	 */
	void *ret = POINTER_OFFSET(remote->data, offsetof(BobRemote::Internal, ret[at]));
	if (ASM.is64Bit()) {
		ASM.mov(asmjit::x86::rdx, (uint64_t)ret);
		ASM.mov(asmjit::x86::qword_ptr(asmjit::x86::rdx), asmjit::x86::rax);
	}
	else {
		ASM.mov(asmjit::x86::edx, (uint64_t)ret);
		ASM.mov(asmjit::x86::dword_ptr(asmjit::x86::edx), asmjit::x86::eax);
	}
}

void BOB_remote_exit(struct BobRemote *remote) {
	asmjit::x86::Assembler ASM(&remote->holder);

	BobModule *kernel32 = BOB_module_open(remote->process, XORSTR("kernel32.dll"), SEARCH_DEFAULT);
	decltype(&ExitThread) _ExitThread = static_cast<decltype(&ExitThread)>(BOB_module_export(remote->process, kernel32, XORSTR("ExitThread")));

	if (ASM.is64Bit()) {
		ASM.mov(asmjit::x86::rcx, asmjit::x86::rax);
		ASM.call(asmjit::imm(_ExitThread));
	}
	else {
		ASM.push(asmjit::x86::eax);
		ASM.call(asmjit::imm(_ExitThread));
	}
}

uint64_t BOB_remote_exec(struct BobRemote *remote, void *arg) {
	if (bob_remote_build(remote)) {
		QueueUserAPC(reinterpret_cast<PAPCFUNC>(remote->code), reinterpret_cast<HANDLE>(remote->thread), reinterpret_cast<ULONG_PTR>(arg));
		if (WaitForSingleObject(remote->event, INFINITE) != WAIT_OBJECT_0) {
			BOB_DEBUG_PRINT(stderr, XORSTR("[Warning] Bob remote code execution failed to SYNC!\n"));
		}
		ResetEvent(remote->event);

		BobRemote::Internal internal;
		if (bob_remote_read(remote, &internal)) {
			BOB_DEBUG_PRINT(stdout, XORSTR("[Info] Bob remote code execution exited with result 0x%p\n"), internal.ret);
			return internal.ret[0];
		}
	}
	return 0;
}

/** \} */

/* -------------------------------------------------------------------- */
/** \name Queries
 * \{ */

uint64_t BOB_remote_saved(struct BobRemote *remote, int idx) {
	BobRemote::Internal internal;
	if (bob_remote_read(remote, &internal)) {
		if (idx < 0 || idx >= static_cast<int>(sizeof(internal.ret) / sizeof(internal.ret[0]))) {
			return 0;
		}
		return internal.ret[idx];
	}
	return 0;
}

int BOB_remote_thread_index(struct BobRemote *remote) {
	return BOB_thread_id(remote->thread);
}

/** \} */
