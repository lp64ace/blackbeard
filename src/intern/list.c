#include "config.h"
#include "list.h"

#include <string.h>

/* -------------------------------------------------------------------- */
/** \name Generic Nodes
 * \{ */

LinkData *LIB_generic_nodeN(void *data) {
	LinkData *link = (LinkData *)bobAlloc(sizeof(LinkData));
	if (link) {
		link->data = data;
	}
	return link;
}

/** \} */

/* -------------------------------------------------------------------- */
/** \name Listbase Insert Methods
 * \{ */

void LIB_addtail(struct ListBase *lb, void *vlink) {
	Link *link = (Link *)vlink;

	if (link == NULL) {
		return;
	}

	link->prev = lb->last;
	link->next = NULL;

	if (lb->last) {
		((Link *)lb->last)->next = link;
	}
	if (lb->first == NULL) {
		lb->first = link;
	}
	lb->last = link;
}

void LIB_addhead(struct ListBase *lb, void *vlink) {
	Link *link = (Link *)vlink;

	if (link == NULL) {
		return;
	}

	link->prev = NULL;
	link->next = lb->first;

	if (lb->first) {
		((Link *)lb->first)->prev = link;
	}
	if (lb->last == NULL) {
		lb->last = link;
	}
	lb->first = link;
}

void LIB_insertlinkbefore(struct ListBase *lb, void *vnextlink, void *vnewlink) {
	Link *nextlink = vnextlink;
	Link *newlink = vnewlink;

	if (newlink == NULL) {
		return;
	}

	if (lb->first == NULL) {
		lb->first = lb->last = newlink;
		return;
	}

	if (nextlink == NULL) {
		newlink->prev = lb->last;
		newlink->next = NULL;
		((Link *)lb->last)->next = newlink;
		lb->last = newlink;
		return;
	}

	if (lb->first == nextlink) {
		lb->first = newlink;
	}

	newlink->next = nextlink;
	newlink->prev = nextlink->prev;
	nextlink->prev = newlink;
	if (newlink->prev) {
		newlink->prev->next = newlink;
	}
}

void LIB_insertlinkafter(struct ListBase *lb, void *vprevlink, void *vnewlink) {
	Link *prevlink = vprevlink;
	Link *newlink = vnewlink;

	if (newlink == NULL) {
		return;
	}

	if (lb->first == NULL) {
		lb->first = newlink;
		lb->last = newlink;
		return;
	}

	if (prevlink == NULL) {
		newlink->prev = NULL;
		newlink->next = (Link *)(lb->first);
		newlink->next->prev = newlink;
		lb->first = newlink;
		return;
	}

	if (lb->last == prevlink) {
		lb->last = newlink;
	}

	newlink->next = prevlink->next;
	newlink->prev = prevlink;
	prevlink->next = newlink;
	if (newlink->next) {
		newlink->next->prev = newlink;
	}
}

void LIB_insertlinkreplace(ListBase *lb, void *vreplacelink, void *vnewlink) {
	Link *l_old = (Link *)vreplacelink;
	Link *l_new = (Link *)vnewlink;

	if (l_old->next != NULL) {
		l_old->next->prev = l_new;
	}
	if (l_old->prev != NULL) {
		l_old->prev->next = l_new;
	}

	l_new->next = l_old->next;
	l_new->prev = l_old->prev;

	if (lb->first == l_old) {
		lb->first = l_new;
	}
	if (lb->last == l_old) {
		lb->last = l_new;
	}
}

/** \} */

/* -------------------------------------------------------------------- */
/** \name Listbase Remove Methods
 * \{ */

void *LIB_pophead(struct ListBase *lb) {
	Link *link = lb->first;
	if (link) {
		LIB_remlink(lb, link);
	}
	return link;
}

void *LIB_poptail(struct ListBase *lb) {
	Link *link = lb->last;
	if (link) {
		LIB_remlink(lb, link);
	}
	return link;
}

void LIB_remlink(struct ListBase *lb, void *vlink) {
	Link *link = (Link *)vlink;

	if (link == NULL) {
		return;
	}

	if (link->next) {
		link->next->prev = link->prev;
	}
	if (link->prev) {
		link->prev->next = link->next;
	}

	if (lb->last == link) {
		lb->last = link->prev;
	}
	if (lb->first == link) {
		lb->first = link->next;
	}
}

void LIB_freelistN(ListBase *listbase) {
	Link *link, *next;

	link = (Link *)listbase->first;
	while (link) {
		next = link->next;
		bobFree(link);
		link = next;
	}

	LIB_listbase_clear(listbase);
}

void LIB_freelinkN(ListBase *lb, void *vlink) {
	Link *link = vlink;

	if (link) {
		LIB_remlink(lb, link);
		bobFree(link);
	}
}

/** \} */

/* -------------------------------------------------------------------- */
/** \name Find Methods
 * \{ */

bool LIB_haslink(const ListBase *lb, void *vlink) {
	if (vlink) {
		for (Link *link = lb->first; link; link = link->next) {
			if (link == (Link *)vlink) {
				return true;
			}
		}
	}
	return false;
}

void *LIB_findptr(const ListBase *lb, const void *ptr, const size_t offset) {
	for (Link *iter = lb->first; iter; iter = iter->next) {
		const void *ptr_iter = *(const void **)POINTER_OFFSET(iter, offset);
		if (ptr_iter == ptr) {
			return iter;
		}
	}

	return NULL;
}

void *LIB_findstr(const ListBase *lb, const char *str, const size_t offset) {
	for (Link *iter = lb->first; iter; iter = iter->next) {
		if (strcmp(POINTER_OFFSET(iter, offset), str) == 0) {
			return iter;
		}
	}

	return NULL;
}

void *LIB_findbytes(const ListBase *lb, const void *bytes, const size_t length, const size_t offset) {
	for (Link *iter = lb->first; iter; iter = iter->next) {
		if (memcmp(POINTER_OFFSET(iter, offset), bytes, length) == 0) {
			return iter;
		}
	}

	return NULL;
}

void *LIB_rfindptr(const ListBase *lb, const void *ptr, const size_t offset) {
	for (Link *iter = lb->last; iter; iter = iter->prev) {
		const void *ptr_iter = *(const void **)POINTER_OFFSET(iter, offset);
		if (ptr_iter == ptr) {
			return iter;
		}
	}

	return NULL;
}

void *LIB_rfindstr(const ListBase *lb, const char *str, const size_t offset) {
	for (Link *iter = lb->last; iter; iter = iter->prev) {
		if (strcmp(POINTER_OFFSET(iter, offset), str) == 0) {
			return iter;
		}
	}

	return NULL;
}

void *LIB_rfindbytes(const ListBase *lb, const void *bytes, const size_t length, const size_t offset) {
	for (Link *iter = lb->first; iter; iter = iter->next) {
		if (memcmp(POINTER_OFFSET(iter, offset), bytes, length) == 0) {
			return iter;
		}
	}

	return NULL;
}

/** \} */

/* -------------------------------------------------------------------- */
/** \name Query Methods
 * \{ */

size_t LIB_listbase_count(const ListBase *lb) {
	size_t length = 0;
	for (Link *iter = lb->first; iter; iter = iter->next) {
		length++;
	}
	return length;
}

/** \} */
