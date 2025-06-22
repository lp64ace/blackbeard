#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <stdbool.h>
#include <pthread.h>
#include <stdio.h>

static pthread_t thread;

volatile bool stop = false;
void *loop(void *userdata) {
	while (!stop) {
		fprintf(stdout, "Hello, this is testdll1.c\n");
	}
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
			
			if (pthread_create(&thread, NULL, loop, (void *)NULL) != 0) {
				return FALSE;
			}
		} break;
		case DLL_PROCESS_DETACH: {
			stop = true;
			
			if (pthread_join(thread, NULL) != 0) {
				return FALSE;
			}
		} break;
	}
	
	return TRUE;
}
