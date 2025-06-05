#ifndef MOD_H
#define MOD_H

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ModuleInformation {
	uintptr_t address;
	char name[512];
	char path[512];
	size_t size;
} ModuleInformation;

enum {
	SEARCH_HEADERS,
	SEARCH_SECTIONS,
	SEARCH_LDR,
};

/**
 * Locates the base address inside the remote process that matches the specified name or path.
 * \note The name encoding must be UTF8 and the resulting pointer is owned by the remote process!
 */
void *BOB_remote_module_address(void *process, const char *name, int search);

#ifdef __cplusplus
}
#endif

#endif
