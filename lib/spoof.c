#include "spoof.h"

#pragma section(".text")
__declspec(allocate(".text")) const unsigned char _fake_addr[] = {0xff, 0x23};

typedef struct ShellParams {
	const void *trampoline_;
	void *function_;
	void *register_;
} ShellParams;

// This is defined inside spoof.asm!
void *_stub(void);

typedef void* (__fastcall* fnSpooferStub)(void *, void *, void *, void *, ShellParams *shell, void *unused, void *, void *, void *, void *, void *, void *, void *, void *, void *, void *, void *);

void *spoof(const void *trampoline, void *function, int nparam, ...) {
	ShellParams params;
	
	params.trampoline_ = trampoline;
	params.function_ = function;
	
	if (!params.trampoline_) {
		params.trampoline_ = _fake_addr;
	}
	
	va_list args;
    va_start(args, nparam);
	void *p_1 = (nparam >= 0x1) ? va_arg(args, void *) : NULL;
	void *p_2 = (nparam >= 0x2) ? va_arg(args, void *) : NULL;
	void *p_3 = (nparam >= 0x3) ? va_arg(args, void *) : NULL;
	void *p_4 = (nparam >= 0x4) ? va_arg(args, void *) : NULL;
	void *p_5 = (nparam >= 0x5) ? va_arg(args, void *) : NULL;
	void *p_6 = (nparam >= 0x6) ? va_arg(args, void *) : NULL;
	void *p_7 = (nparam >= 0x7) ? va_arg(args, void *) : NULL;
	void *p_8 = (nparam >= 0x8) ? va_arg(args, void *) : NULL;
	void *p_9 = (nparam >= 0x9) ? va_arg(args, void *) : NULL;
	void *p_a = (nparam >= 0xa) ? va_arg(args, void *) : NULL;
	void *p_b = (nparam >= 0xb) ? va_arg(args, void *) : NULL;
	void *p_c = (nparam >= 0xc) ? va_arg(args, void *) : NULL;
	void *p_d = (nparam >= 0xd) ? va_arg(args, void *) : NULL;
	void *p_e = (nparam >= 0xe) ? va_arg(args, void *) : NULL;
	void *p_f = (nparam >= 0xf) ? va_arg(args, void *) : NULL;
	va_end(args);
	
	return ((fnSpooferStub)_stub)(p_1, p_2, p_3, p_4, &params, NULL, p_5, p_6, p_7, p_8, p_9, p_a, p_b, p_c, p_d, p_e, p_f);
}
