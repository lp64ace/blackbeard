#ifndef LIST_H
#define LIST_H

#include "config.h"

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* -------------------------------------------------------------------- */
/** \name Generic Nodes
 * \{ */

typedef struct Link {
	struct Link *prev, *next;
} Link;

typedef struct ListBase {
	void *first, *last;
} ListBase;

/** \} */

/* -------------------------------------------------------------------- */
/** \name Generic Nodes
 * \{ */

typedef struct LinkData {
	struct LinkData *prev, *next;

	void *data;
} LinkData;

/** Creates a new LinkData node with the specified data. */
struct LinkData *LIB_generic_nodeN(void *data);

/** \} */

/* -------------------------------------------------------------------- */
/** \name Insert Methods
 * \{ */

/**
 * Inserts a Link at the end of a ListBase.
 * Items cannot be shared between multiple ListBase lists.
 *
 * \param lb The ListBase into which the Link will be inserted.
 * \param vlink The Link structure to be inserted.
 */
void LIB_addtail(ListBase *lb, void *vlink);
/**
 * Inserts a Link at the beginning of a ListBase.
 * Items cannot be shared between multiple ListBase lists.
 *
 * \param lb The ListBase into which the Link will be inserted.
 * \param vlink The Link structure to be inserted.
 */
void LIB_addhead(ListBase *lb, void *vlink);

/**
 * Inserts a new Link into a ListBase before an existing Link.
 *
 * \param lb The ListBase into which the new Link will be inserted.
 * \param vnextlink The existing Link before which the new Link will be inserted.
 * \param vnewlink The new Link structure to be inserted.
 */
void LIB_insertlinkbefore(ListBase *lb, void *vnextlink, void *vnewlink);
/**
 * Inserts a new Link into a ListBase after an existing Link.
 *
 * \param lb The ListBase into which the new Link will be inserted.
 * \param vprevlink The existing Link after which the new Link will be inserted.
 * \param vnewlink The new Link structure to be inserted.
 */
void LIB_insertlinkafter(ListBase *lb, void *vprevlink, void *vnewlink);

/**
 * Replaces an existing Link in a ListBase with a new Link without changing its position.
 *
 * \param lb The ListBase from which the existing Link will be replaced.
 * \param vreplacelink The existing Link that will be removed from the ListBase.
 * \param vnewlink The new Link that will replace `vreplacelink`.
 */
void LIB_insertlinkreplace(ListBase *lb, void *vreplacelink, void *vnewlink);

/** \} */

/* -------------------------------------------------------------------- */
/** \name Remove Methods
 * \{ */

/**
 * Removes and returns the first Link from a ListBase.
 *
 * \param lb The ListBase from which the first Link will be removed.
 * \return A pointer to the removed Link, or NULL if the ListBase is empty.
 */
void *LIB_pophead(ListBase *lb);
/**
 * Removes and returns the last Link from a ListBase.
 *
 * \param lb The ListBase from which the last Link will be removed.
 * \return A pointer to the removed Link, or NULL if the ListBase is empty.
 */
void *LIB_poptail(ListBase *lb);

/**
 * Removes a specified Link from a ListBase.
 *
 * \param lb The ListBase from which the specified Link will be removed.
 * \param vlink The Link structure to be removed.
 * \note The Link is not deallocated; you must handle memory management if necessary.
 */
void LIB_remlink(ListBase *lb, void *vlink);

/**
 * Removes and frees all elements in a ListBase using guarded memory allocation.
 *
 * \param listbase The ListBase whose contents will be freed.
 */
void LIB_freelistN(ListBase *listbase);
/** Removes and frees a single element from the list. */
void LIB_freelinkN(ListBase *lb, void *vlink);

/** \} */

/* -------------------------------------------------------------------- */
/** \name Search Methods
 * \{ */

/**
 * Checks if a specific Link exists within a ListBase.
 *
 * \param lb The ListBase to search within.
 * \param vlink The Link structure to check for.
 *
 * \return `true` if the Link exists in the ListBase, `false` otherwise.
 */
bool LIB_haslink(const ListBase *lb, void *vlink);

/**
 * Finds and returns the first Link in a ListBase where;
 * The specified pointer matches a value at a given offset.
 *
 * \param lb The ListBase to search within.
 * \param ptr The pointer value to search for.
 * \param offset The byte offset within each Link where the pointer value is located.
 *
 * \return A pointer to the found Link, or NULL if no match is found.
 */
void *LIB_findptr(const ListBase *lb, const void *ptr, const size_t offset);
/**
 * Finds and returns the first Link in a ListBase where;
 * The specified string matches a value at a given offset.
 *
 * \param lb The ListBase to search within.
 * \param str The string to search for.
 * \param offset The byte offset within each Link where the string is located.
 *
 * \return A pointer to the found Link, or NULL if no match is found.
 */
void *LIB_findstr(const ListBase *lb, const char *str, const size_t offset);
/**
 * Finds and returns the first Link in a ListBase where;
 * The specified sequence of bytes matches a value at a given offset.
 *
 * \param lb The ListBase to search within.
 * \param bytes The sequence of bytes to search for.
 * \param length The length of the byte sequence.
 * \param offset The byte offset within each Link where the byte sequence is located.
 *
 * \return A pointer to the found Link, or NULL if no match is found.
 */
void *LIB_findbytes(const ListBase *lb, const void *bytes, const size_t length, const size_t offset);

/**
 * Finds and returns the last Link in a ListBase where;
 * The specified pointer matches a value at a given offset.
 *
 * \param lb The ListBase to search within.
 * \param ptr The pointer value to search for.
 * \param offset The byte offset within each Link where the pointer value is located.
 *
 * \return A pointer to the found Link, or NULL if no match is found.
 */
void *LIB_rfindptr(const ListBase *lb, const void *ptr, const size_t offset);
/**
 * Finds and returns the last Link in a ListBase where;
 * The specified string matches a value at a given offset.
 *
 * \param lb The ListBase to search within.
 * \param str The string to search for.
 * \param offset The byte offset within each Link where the string is located.
 *
 * \return A pointer to the found Link, or NULL if no match is found.
 */
void *LIB_rfindstr(const ListBase *lb, const char *str, const size_t offset);
/**
 * Finds and returns the last Link in a ListBase where;
 * The specified sequence of bytes matches a value at a given offset.
 *
 * \param lb The ListBase to search within.
 * \param bytes The sequence of bytes to search for.
 * \param length The length of the byte sequence.
 * \param offset The byte offset within each Link where the byte sequence is located.
 *
 * \return A pointer to the found Link, or NULL if no match is found.
 */
void *LIB_rfindbytes(const ListBase *lb, const void *bytes, const size_t length, const size_t offset);

/** \} */

/* -------------------------------------------------------------------- */
/** \name Query Methods
 * \{ */

/** Returns the number of elements that are stored in the specified listbase. */
size_t LIB_listbase_count(const ListBase *listbase);

/** Checks if a ListBase is empty. */
BOB_INLINE bool LIB_listbase_is_empty(const ListBase *listbase);
/** Checks if a ListBase contains exactly one Link. */
BOB_INLINE bool LIB_listbase_is_single(const ListBase *listbase);

/** Clears all Links from a ListBase, resetting it to an empty state. */
BOB_INLINE void LIB_listbase_clear(ListBase *listbase);

/** \} */

#ifdef __cplusplus
}
#endif

BOB_INLINE bool LIB_listbase_is_empty(const ListBase *listbase) {
	return (listbase->first == NULL && listbase->first == listbase->last);
}

BOB_INLINE bool LIB_listbase_is_single(const ListBase *listbase) {
	return (listbase->first && listbase->first == listbase->last);
}

BOB_INLINE void LIB_listbase_clear(ListBase *listbase) {
	listbase->first = listbase->last = NULL;
}

/* -------------------------------------------------------------------- */
/** \name Iteration Macros
 * \{ */

#define LISTBASE_FOREACH(type, var, list) for (type var = (type)((list)->first); var != NULL; var = (type)(((Link *)(var))->next))

#define LISTBASE_FOREACH_BACKWARD(type, var, list) for (type var = (type)((list)->last); var != NULL; var = (type)(((Link *)(var))->prev))

/**
 * A version of #LISTBASE_FOREACH that supports incrementing an index variable at every step.
 * Including this in the macro helps prevent mistakes where "continue" mistakenly skips the
 * incrementation.
 */
#define LISTBASE_FOREACH_INDEX(type, var, list, index_var) for (type var = (((void)(index_var = 0)), (type)((list)->first)); var != NULL; var = (type)(((Link *)(var))->next), index_var++)

/**
 * A version of #LISTBASE_FOREACH that supports removing the item we're looping over.
 */
#define LISTBASE_FOREACH_MUTABLE(type, var, list) for (type var = (type)((list)->first), *var##_iter_next; ((var != NULL) ? ((void)(var##_iter_next = (type)(((Link *)(var))->next)), 1) : 0); var = var##_iter_next)

/**
 * A version of #LISTBASE_FOREACH_BACKWARD that supports removing the item we're looping over.
 */
#define LISTBASE_FOREACH_BACKWARD_MUTABLE(type, var, list) for (type var = (type)((list)->last), *var##_iter_prev; ((var != NULL) ? ((void)(var##_iter_prev = (type)(((Link *)(var))->prev)), 1) : 0); var = var##_iter_prev)

/** \} */

#endif
