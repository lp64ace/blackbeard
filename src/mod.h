#ifndef MOD_H
#define MOD_H

#include "proc.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct BobModule BobModule;

/* -------------------------------------------------------------------- */
/** \name Module Native
 * \{ */

enum {
	SEARCH_LOADER = 1 << 0,
	SEARCH_HEADER = 1 << 1,
	SEARCH_SECTION = 1 << 2,

	SEARCH_DEFAULT = SEARCH_LOADER,
	SEARCH_ALL = 0xFF,
};

/**
 * Painfully slow method to locate a module in a remote process.
 */
struct BobModule *BOB_module_open(struct BobProc *process, const char *name, int search);
/** Release any address used by #BobModule, although this function does nothing. */
void BOB_module_close(struct BobModule *module);

void *BOB_module_export(struct BobProc *process, struct BobModule *module, const char *name);

/** \} */

#ifdef __cplusplus
}
#endif

#endif
