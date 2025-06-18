#ifndef __BOB_MODULE_H__
#define __BOB_MODULE_H__

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

struct BobProcess;

/* -------------------------------------------------------------------- */
/** \name Implementation
 * \{ */

typedef struct BobModule BobModule;

enum {
	SEARCH_LOADER = 1 << 0,
	SEARCH_HEADER = 1 << 1,
	SEARCH_SECTION = 1 << 2,

	SEARCH_DEFAULT = SEARCH_LOADER,
	SEARCH_ALL = 0xFF,
};

struct BobModule *BOB_module_open_by_schema(struct BobProcess *process, const char *name, int mode);
struct BobModule *BOB_module_open_by_name(struct BobProcess *process, const char *name, int mode);
struct BobModule *BOB_module_open_by_wname(struct BobProcess *process, const wchar_t *name, int mode);

// No need to call this function!
void BOB_module_close(struct BobModule *module);

/** \} */

/* -------------------------------------------------------------------- */
/** \name Query
 * \{ */

void *BOB_module_export(struct BobProcess *process, struct BobModule *module, const char *name);

/** \} */

#ifdef __cplusplus
}
#endif

#endif
