#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <iostream>
#include <vector>
#include <stdexcept>

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

			for (int i = 1; i <= 16; i++) {
				vector.push_back(i);
			}

			try {
				throw std::runtime_error("Hello, this is testdll3.cc!");
			} catch (const std::runtime_error &e) {
				std::cout << "Caught exception: " << e.what() << std::endl;
			}
		} break;
	}

	return TRUE;
}
