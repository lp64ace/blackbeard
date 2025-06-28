#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <stdbool.h>
#include <pthread.h>
#include <stdio.h>

static pthread_t mThreadId;

#include <iostream>
#include <vector>

static unsigned char *get() {
	static thread_local unsigned char num = 4;
	return &num;
}

void *dispatch(void *userdata) {
	while (*get()) {
		std::cout << "[Thread] Hello, this is testdll2.cc " << (int)*get() << std::endl;
		(*get())--;
	}

	return NULL;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, LPVOID unused) {
	switch (dwReason) {
		case DLL_PROCESS_ATTACH: {
			DisableThreadLibraryCalls(hModule);
			
			if (AllocConsole() || AttachConsole(ATTACH_PARENT_PROCESS)) {
				(void)freopen("CONIN$", "r", stdin);
				(void)freopen("CONOUT$", "w", stderr);
				(void)freopen("CONOUT$", "w", stdout);
			}

			while (*get()) {
				std::cout << "[Main] Hello, this is testdll2.cc " << (int)*get() << std::endl;
				(*get())--;
			}

			if (pthread_create(&mThreadId, NULL, dispatch, (void *)NULL) != 0) {
				return FALSE;
			}
		} break;
	}
	
	return TRUE;
}
