#ifndef PROC_H
#define PROC_H

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct BobProc BobProc;

/* -------------------------------------------------------------------- */
/** \name Procedure Native
 * \{ */

/**
 * The Process Environment Block is a data structure in the Windows NT operating system family.
 * 
 * It is an opaque data structure that is used by the operating system internally, 
 * most of whose fields are not intended for use by anything other than the operating system.
 * 
 * \return The result is a pointer to an address owned by the remote process indicating the base address of the process.
 */
void *BOB_process_information(const struct BobProc *process, void *peb);

enum {
	PROTECT_NO,
	PROTECT_R = 1 << 0,
	PROTECT_W = 1 << 1,
	PROTECT_E = 1 << 2,
};

/**
 * Reserve and commit memory within the virtual address space of a specified process.
 * The function initializes the memory it allocates to zero.
 * 
 * \param protect The memory protection for the region of pages to be allocated, use any of the ALLOC_XXX constants.
 */
void *BOB_process_alloc(const struct BobProc *process, const void *address, size_t length, int protect);
void *BOB_process_duplicate(const struct BobProc *process, const void *buffer, size_t length, int protect);
/** Changes the protection on a region of committed pages in the virtual address space of a specified process. */
bool BOB_process_protect(const struct BobProc *process, const void *address, size_t length, int protect);
/** Releases a region of memory within the virtual address space of a specified process. */
bool BOB_process_free(const struct BobProc *process, const void *address);

size_t BOB_process_read(const struct BobProc *process, const void *remote, void *local, size_t length);
size_t BOB_process_write(const struct BobProc *process, const void *remote, const void *local, size_t length);

struct BobProc *BOB_process_open_ex(int id);
struct BobProc *BOB_process_open(const char *name);
struct BobProc *BOB_process_self(void);

void BOB_process_close(struct BobProc *process);

/** \} */

/* -------------------------------------------------------------------- */
/** \name Queries
 * \{ */

void *BOB_process_address(const struct BobProc *process);
void *BOB_process_handle(const struct BobProc *process);

int BOB_process_index(const struct BobProc *process);

/** \} */

#ifdef __cplusplus
}
#endif

#endif
