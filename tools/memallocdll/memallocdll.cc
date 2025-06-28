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

			try {
				// C allocation
				void* mem = malloc(64);
				if (mem) {
					std::cout << "C   Alloc " << mem << std::endl;
					free(mem);
				}
				
				// C++ allocation
				int* arr = new int[10];
				for (int i = 0; i < 10; ++i) {
					arr[i] = i * 2;
				}
				std::cout << "C++ Alloc " << arr << std::endl;
				delete[] arr;
				
				// STL allocation
				std::vector<int> vec(10, 123);
				std::cout << "STL Alloc " << vec.data() << std::endl;
			} catch (const std::exception& e) {
				std::cerr << "Caught exception: " << e.what() << std::endl;
			}
		} break;
	}

	return TRUE;
}
