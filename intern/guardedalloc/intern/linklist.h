#ifndef LINKLIST_H
#define LINKLIST_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* -------------------------------------------------------------------- */
/** \name Structures
 * \{ */

/**
 * #Link is a structure that can be stored inside a #ListBase.
 */
typedef struct Link {
	struct Link *prev, *next;
} Link;

/**
 * #ListBase is a double linked list of #Links.
 */
typedef struct ListBase {
	struct Link *first, *last;
} ListBase;

/** \} */

/* -------------------------------------------------------------------- */
/** \name Methods
 * \{ */

/**
 * Insert a new #Link in the end of the #ListBase.
 *
 * \param[in] listbase The list where we want to append the new link.
 * \param[in] vlink The link we want to append in the list.
 *
 * \note If #vlink is already in the #ListBase this has undefined behaviour.
 */
void addlink(struct ListBase *listbase, void *vlink);

/**
 * Removes a #Link from the #ListBase.
 *
 *
 * \param[in] listbase The list where we want to remove the link from.
 * \param[in] vlink The link we want to remove from the list.
 *
 * \note If #vlink is not in the #ListBase this has undefined behaviour.
 */
void remlink(struct ListBase *listbase, void *vlink);

/** \} */

/* -------------------------------------------------------------------- */
/** \name Utils
 * \{ */

/* clang-format off */

/**
 * Loop over a #ListBase, the #ListBase should not be altered during this loop.
 */
#define LISTBASE_FOREACH(type, var, list) \
	for (type var = (type)((list)->first); var != NULL; var = (type)(((Link *)(var))->next))

/**
 * A version of #LISTBASE_FOREACH that supports removing the item we're looping over.
 */
#define LISTBASE_FOREACH_MUTABLE(type, var, list) \
  for (type var = (type)((list)->first), *var##_iter_next; \
       ((var != NULL) ? ((void)(var##_iter_next = (type)(((Link *)(var))->next)), 1) : 0); \
       var = var##_iter_next)

/* clang-format on */

/** \} */

#ifdef __cplusplus
}
#endif

#endif	// LINKLIST_H
