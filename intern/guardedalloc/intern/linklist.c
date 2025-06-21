#include "linklist.h"
#include <stddef.h>
#include <stdint.h>

void addlink(struct ListBase *listbase, void *vlink) {
	Link *link = (Link *)vlink;

	if (link) {
		link->prev = listbase->last;
		link->next = NULL;

		if (listbase->first == NULL) {
			listbase->first = link;
		}
		if (listbase->last) {
			listbase->last->next = link;
		}
		listbase->last = link;
	}
}

void remlink(struct ListBase *listbase, void *vlink) {
	Link *link = (Link *)vlink;

	if (link) {
		if (link->prev) {
			link->prev->next = link->next;
		}
		if (link->next) {
			link->next->prev = link->prev;
		}

		if (listbase->last == link) {
			listbase->last = link->prev;
		}
		if (listbase->first == link) {
			listbase->first = link->next;
		}
	}
}
