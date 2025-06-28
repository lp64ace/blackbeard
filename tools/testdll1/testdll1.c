#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <stdbool.h>
#include <pthread.h>
#include <stdio.h>

int count = 0xdead;

BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, LPVOID unused) {
	switch (dwReason) {
		case DLL_PROCESS_ATTACH: {
			DisableThreadLibraryCalls(hModule);
			
			if (AllocConsole() || AttachConsole(ATTACH_PARENT_PROCESS)) {
				(void)freopen("CONIN$", "r", stdin);
				(void)freopen("CONOUT$", "w", stderr);
				(void)freopen("CONOUT$", "w", stdout);
			}
			
			fprintf(stdout, "Hello, this is testdll1.c 0x%x\n", count);
		} break;
	}
	
	return TRUE;
}
