#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>

static pthread_t mThreadId;

#include <iostream>
#include <vector>

void *dispatch(void *userdata) {
	std::vector<int> vector;
	while (vector.size() < 16) {
		vector.push_back(vector.size());
		std::cout << "[Thread] Hello, this is testdll3.cc " << vector.size() << std::endl;
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
			
			std::vector<int> vector;
			while (vector.size() < 16) {
				vector.push_back(vector.size());
				std::cout << "[Main] Hello, this is testdll3.cc " << vector.size() << std::endl;
			}

			if (pthread_create(&mThreadId, NULL, dispatch, (void *)NULL) != 0) {
				return FALSE;
			}
		} break;
		case DLL_PROCESS_DETACH: {
			// Nothing to do!
		} break;
	}
	
	return TRUE;
}
