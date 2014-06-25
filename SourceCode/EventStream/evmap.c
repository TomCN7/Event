/*
 * Copyright (c) 2007-2012 Niels Provos and Nick Mathewson
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
#include "stdafx.h"
#include "config.h"

#ifdef _WIN32
#include <winsock2.h>
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#undef WIN32_LEAN_AND_MEAN
#endif
#include <sys/types.h>
#if !defined(_WIN32) && defined(EVENT__HAVE_SYS_TIME_H)
#include <sys/time.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#ifndef _WIN32
#include <unistd.h>
#endif
#include <errno.h>
#include <string.h>
#include <time.h>

#include "event.h"
#include "event-internal.h"
#include "evmap-internal.h"
#include "mm-internal.h"

/** An entry for an evmap_io list: notes all the events that want to read or
	write on a given fd, and the number of each.
  */
struct evmap_io
{
	struct event_dlist events;
	uint16_t nread;
	uint16_t nwrite;
	uint16_t nclose;
};

/* On some platforms, fds start at 0 and increment by 1 as they are
   allocated, and old numbers get used.  For these platforms, we
   implement io maps just like signal maps: as an array of pointers to
   struct evmap_io.  But on other platforms (windows), sockets are not
   0-indexed, not necessarily consecutive, and not necessarily reused.
   There, we use a hashtable to implement evmap_io.
*/
#ifdef EVMAP_USE_HT
struct event_map_entry {
	HT_ENTRY(event_map_entry) map_node;
	evutil_socket_t fd;
	union { /* This is a union in case we need to make more things that can
			   be in the hashtable. */
		struct evmap_io evmap_io;
	} ent;
};

/* Helper used by the event_io_map hashtable code; tries to return a good hash
 * of the fd in e->fd. */
static inline unsigned
hashsocket(struct event_map_entry *e)
{
	/* On win32, in practice, the low 2-3 bits of a SOCKET seem not to
	 * matter.  Our hashtable implementation really likes low-order bits,
	 * though, so let's do the rotate-and-add trick. */
	unsigned h = (unsigned) e->fd;
	h += (h >> 2) | (h << 30);
	return h;
}

/* Helper used by the event_io_map hashtable code; returns true iff e1 and e2
 * have the same e->fd. */
static inline int
eqsocket(struct event_map_entry *e1, struct event_map_entry *e2)
{
	return e1->fd == e2->fd;
}

HT_PROTOTYPE(event_io_map, event_map_entry, map_node, hashsocket, eqsocket)
HT_GENERATE(event_io_map, event_map_entry, map_node, hashsocket, eqsocket,
			0.5, mm_malloc, mm_realloc, mm_free)

#define GET_IO_SLOT(x, map, slot, type)					\
	do {								\
		struct event_map_entry key_, *ent_;			\
		key_.fd = slot;						\
		ent_ = HT_FIND(event_io_map, map, &key_);		\
		(x) = ent_ ? &ent_->ent.type : NULL;			\
	} while (0);

#define GET_IO_SLOT_AND_CTOR(x, map, slot, type, ctor, fdinfo_len)	\
	do {								\
		struct event_map_entry key_, *ent_;			\
		key_.fd = slot;						\
		HT_FIND_OR_INSERT_(event_io_map, map_node, hashsocket, map, \
		    event_map_entry, &key_, ptr,			\
		    {							\
			    ent_ = *ptr;				\
		    },							\
		    {							\
			    ent_ = mm_calloc(1,sizeof(struct event_map_entry)+fdinfo_len); \
			    if (EVUTIL_UNLIKELY(ent_ == NULL))		\
				    return (-1);			\
			    ent_->fd = slot;				\
			    (ctor)(&ent_->ent.type);			\
			    HT_FOI_INSERT_(map_node, map, &key_, ent_, ptr) \
				});					\
		(x) = &ent_->ent.type;					\
	} while (0)

void evmap_io_initmap_(struct event_io_map *ctx)
{
	HT_INIT(event_io_map, ctx);
}

void evmap_io_clear_(struct event_io_map *ctx)
{
	struct event_map_entry **ent, **next, *this;
	for (ent = HT_START(event_io_map, ctx); ent; ent = next) {
		this = *ent;
		next = HT_NEXT_RMV(event_io_map, ctx, ent);
		mm_free(this);
	}
	HT_CLEAR(event_io_map, ctx); /* remove all storage held by the ctx. */
}

#else

/* Set the variable 'x' to the field in event_map 'map' with fields of type
   'struct type *' corresponding to the fd or signal 'slot'.  Set 'x' to NULL
   if there are no entries for 'slot'.  Does no bounds-checking. */
#define GET_IO_SLOT(x, map, slot, type)			\
	(x) = (struct type *)((map)->entries[slot])
/* As GET_SLOT, but construct the entry for 'slot' if it is not present,
   by allocating enough memory for a 'struct type', and initializing the new
   value by calling the function 'ctor' on it.  Makes the function
   return -1 on allocation failure.
 */
#define GET_IO_SLOT_AND_CTOR(x, map, slot, type, ctor, fdinfo_len)	\
	do {								\
		if ((map)->entries[slot] == NULL) {			\
			(map)->entries[slot] =				\
			    mm_calloc(1,sizeof(struct type)+fdinfo_len); \
			if (EVUTIL_UNLIKELY((map)->entries[slot] == NULL)) \
				return (-1);				\
			(ctor)((struct type *)(map)->entries[slot]);	\
		}							\
		(x) = (struct type *)((map)->entries[slot]);		\
	} while (0)

#define FDINFO_OFFSET sizeof(struct evmap_io)
void
evmap_io_initmap_(struct event_io_map* ctx)
{

}
void
evmap_io_clear_(struct event_io_map* ctx)
{

}
#endif

#if 0
/** Expand 'map' with new entries of width 'msize' until it is big enough
	to store a value in 'slot'.
 */
static int
evmap_make_space(struct event_signal_map *map, int slot, int msize)
{
	if (map->nentries <= slot) {
		int nentries = map->nentries ? map->nentries : 32;
		void **tmp;

		while (nentries <= slot)
			nentries <<= 1;

		tmp = (void **)mm_realloc(map->entries, nentries * msize);
		if (tmp == NULL)
			return (-1);

		memset(&tmp[map->nentries], 0,
		    (nentries - map->nentries) * msize);

		map->nentries = nentries;
		map->entries = tmp;
	}

	return (0);
}
#endif

/* code specific to file descriptors */

/** Constructor for struct evmap_io */
static void
evmap_io_init(struct evmap_io *entry)
{
	LIST_INIT(&entry->events);
	entry->nread = 0;
	entry->nwrite = 0;
	entry->nclose = 0;
}


/* return -1 on error, 0 on success if nothing changed in the event backend,
 * and 1 on success if something did. */
int
evmap_io_add_(struct event_base *base, evutil_socket_t fd, struct event *ev)
{
	const struct eventop *evsel = base->evsel;
	struct event_io_map *io = &base->io;
	struct evmap_io *ctx = NULL;
	int nread, nwrite, nclose, retval = 0;
	short res = 0, old = 0;
	struct event *old_ev;

	EVUTIL_ASSERT(fd == ev->ev_fd);

	if (fd < 0)
		return 0;

#ifndef EVMAP_USE_HT
	if (fd >= io->nentries) {
		if (evmap_make_space(io, fd, sizeof(struct evmap_io *)) == -1)
			return (-1);
	}
#endif
	GET_IO_SLOT_AND_CTOR(ctx, io, fd, evmap_io, evmap_io_init,
						 evsel->fdinfo_len);

	nread = ctx->nread;
	nwrite = ctx->nwrite;
	nclose = ctx->nclose;

	if (nread)
		old |= EV_READ;
	if (nwrite)
		old |= EV_WRITE;
	if (nclose)
		old |= EV_CLOSED;

	if (ev->ev_events & EV_READ) {
		if (++nread == 1)
			res |= EV_READ;
	}
	if (ev->ev_events & EV_WRITE) {
		if (++nwrite == 1)
			res |= EV_WRITE;
	}
	if (ev->ev_events & EV_CLOSED) {
		if (++nclose == 1)
			res |= EV_CLOSED;
	}
	if (EVUTIL_UNLIKELY(nread > 0xffff || nwrite > 0xffff || nclose > 0xffff)) {
		event_warnx("Too many events reading or writing on fd %d",
		    (int)fd);
		return -1;
	}
	if ((old_ev = LIST_FIRST(&ctx->events)) &&
	    (old_ev->ev_events&EV_ET) != (ev->ev_events&EV_ET)) {
		event_warnx("Tried to mix edge-triggered and non-edge-triggered"
		    " events on fd %d", (int)fd);
		return -1;
	}

	if (res) {
		void *extra = ((char*)ctx) + sizeof(struct evmap_io);
		/* XXX(niels): we cannot mix edge-triggered and
		 * level-triggered, we should probably assert on
		 * this. */
		if (evsel->add(base, ev->ev_fd,
			old, (ev->ev_events & EV_ET) | res, extra) == -1)
			return (-1);
		retval = 1;
	}

	ctx->nread = (uint16_t) nread;
	ctx->nwrite = (uint16_t) nwrite;
	ctx->nclose = (uint16_t) nclose;
	LIST_INSERT_HEAD(&ctx->events, ev, ev_io_next);

	return (retval);
}

/* return -1 on error, 0 on success if nothing changed in the event backend,
 * and 1 on success if something did. */
int
evmap_io_del_(struct event_base *base, evutil_socket_t fd, struct event *ev)
{
	const struct eventop *evsel = base->evsel;
	struct event_io_map *io = &base->io;
	struct evmap_io *ctx;
	int nread, nwrite, nclose, retval = 0;
	short res = 0, old = 0;

	if (fd < 0)
		return 0;

	EVUTIL_ASSERT(fd == ev->ev_fd);

#ifndef EVMAP_USE_HT
	if (fd >= io->nentries)
		return (-1);
#endif

	GET_IO_SLOT(ctx, io, fd, evmap_io);

	nread = ctx->nread;
	nwrite = ctx->nwrite;
	nclose = ctx->nclose;

	if (nread)
		old |= EV_READ;
	if (nwrite)
		old |= EV_WRITE;
	if (nclose)
		old |= EV_CLOSED;

	if (ev->ev_events & EV_READ) {
		if (--nread == 0)
			res |= EV_READ;
		EVUTIL_ASSERT(nread >= 0);
	}
	if (ev->ev_events & EV_WRITE) {
		if (--nwrite == 0)
			res |= EV_WRITE;
		EVUTIL_ASSERT(nwrite >= 0);
	}
	if (ev->ev_events & EV_CLOSED) {
		if (--nclose == 0)
			res |= EV_CLOSED;
		EVUTIL_ASSERT(nclose >= 0);
	}

	if (res) {
		void *extra = ((char*)ctx) + sizeof(struct evmap_io);
		if (evsel->del(base, ev->ev_fd, old, res, extra) == -1) {
			retval = -1;
		} else {
			retval = 1;
		}
	}

	ctx->nread = nread;
	ctx->nwrite = nwrite;
	ctx->nclose = nclose;
	LIST_REMOVE(ev, ev_io_next);

	return (retval);
}

void
evmap_io_active_(struct event_base *base, evutil_socket_t fd, short events)
{
	struct event_io_map *io = &base->io;
	struct evmap_io *ctx;
	struct event *ev;

#ifndef EVMAP_USE_HT
	if (fd < 0 || fd >= io->nentries)
		return;
#endif
	GET_IO_SLOT(ctx, io, fd, evmap_io);

	if (NULL == ctx)
		return;
	LIST_FOREACH(ev, &ctx->events, ev_io_next)
    {
		if (ev->ev_events & events)
			event_active(ev, ev->ev_events & events);
	}
}

void *
evmap_io_get_fdinfo_(struct event_io_map *map, evutil_socket_t fd)
{
	struct evmap_io *ctx;
	GET_IO_SLOT(ctx, map, fd, evmap_io);
	if (ctx)
		return ((char*)ctx) + sizeof(struct evmap_io);
	else
		return NULL;
}

/* Callback type for evmap_io_foreach_fd */
typedef int (*evmap_io_foreach_fd_cb)(
	struct event_base *, evutil_socket_t, struct evmap_io *, void *);

/* Multipurpose helper function: Iterate over every file descriptor event_base
 * for which we could have EV_READ or EV_WRITE events.  For each such fd, call
 * fn(base, signum, evmap_io, arg), where fn is the user-provided
 * function, base is the event_base, signum is the signal number, evmap_io
 * is an evmap_io structure containing a list of events pending on the
 * file descriptor, and arg is the user-supplied argument.
 *
 * If fn returns 0, continue on to the next signal. Otherwise, return the same
 * value that fn returned.
 *
 * Note that there is no guarantee that the file descriptors will be processed
 * in any particular order.
 */
static int
evmap_io_foreach_fd(struct event_base *base,
    evmap_io_foreach_fd_cb fn,
    void *arg)
{
	evutil_socket_t fd;
	struct event_io_map *iomap = &base->io;
	int r = 0;
#ifdef EVMAP_USE_HT
	struct event_map_entry **mapent;
	HT_FOREACH(mapent, event_io_map, iomap) {
		struct evmap_io *ctx = &(*mapent)->ent.evmap_io;
		fd = (*mapent)->fd;
#else
	for (fd = 0; fd < iomap->nentries; ++fd) {
		struct evmap_io *ctx = iomap->entries[fd];
		if (!ctx)
			continue;
#endif
		if ((r = fn(base, fd, ctx, arg)))
			break;
	}
	return r;
}

/* Helper for evmap_reinit_: tell the backend to add every fd for which we have
 * pending events, with the appropriate combination of EV_READ, EV_WRITE, and
 * EV_ET. */
static int
evmap_io_reinit_iter_fn(struct event_base *base, evutil_socket_t fd,
    struct evmap_io *ctx, void *arg)
{
	const struct eventop *evsel = base->evsel;
	void *extra;
	int *result = arg;
	short events = 0;
	struct event *ev;
	EVUTIL_ASSERT(ctx);

	extra = ((char*)ctx) + sizeof(struct evmap_io);
	if (ctx->nread)
		events |= EV_READ;
	if (ctx->nwrite)
		events |= EV_WRITE;
	if (ctx->nclose)
		events |= EV_CLOSED;
	if (evsel->fdinfo_len)
		memset(extra, 0, evsel->fdinfo_len);
	if (events &&
	    (ev = LIST_FIRST(&ctx->events)) &&
	    (ev->ev_events & EV_ET))
		events |= EV_ET;
	if (evsel->add(base, fd, 0, events, extra) == -1)
		*result = -1;

	return 0;
}

int
evmap_reinit_(struct event_base *base)
{
	int result = 0;

	evmap_io_foreach_fd(base, evmap_io_reinit_iter_fn, &result);
	if (result < 0)
		return -1;

    return 0;
}

/* Helper for evmap_delete_all_: delete every event in an event_dlist. */
static int
delete_all_in_dlist(struct event_dlist *dlist)
{
	struct event *ev;
	while ((ev = LIST_FIRST(dlist)))
		event_del_general(ev);
	return 0;
}

/* Helper for evmap_delete_all_: delete every event pending on an fd. */
static int
evmap_io_delete_all_iter_fn(struct event_base *base,
    evutil_socket_t fd, struct evmap_io *io_info, void *arg)
{
	return delete_all_in_dlist(&io_info->events);
}

void evmap_delete_all_(struct event_base *base)
{
	evmap_io_foreach_fd(base, evmap_io_delete_all_iter_fn, NULL);
}

/* Helper for evmap_check_integrity_: verify that all of the events pending on
 * given fd are set up correctly, and that the nread and nwrite counts on that
 * fd are correct. */
static int evmap_io_check_integrity_fn(struct event_base *base,
    evutil_socket_t fd, struct evmap_io *io_info, void *arg)
{
	struct event *ev;
	int n_read = 0, n_write = 0, n_close = 0;

	/* First, make sure the list itself isn't corrupt. Otherwise,
	 * running LIST_FOREACH could be an exciting adventure. */
	EVUTIL_ASSERT_LIST_OK(&io_info->events, event, ev_io_next);

	LIST_FOREACH(ev, &io_info->events, ev_io_next)
    {
		EVUTIL_ASSERT(ev->ev_flags & EVLIST_INSERTED);
		EVUTIL_ASSERT(ev->ev_fd == fd);
		EVUTIL_ASSERT((ev->ev_events & (EV_READ|EV_WRITE|EV_CLOSED)));
		if (ev->ev_events & EV_READ)
			++n_read;
		if (ev->ev_events & EV_WRITE)
			++n_write;
		if (ev->ev_events & EV_CLOSED)
			++n_close;
	}

	EVUTIL_ASSERT(n_read == io_info->nread);
	EVUTIL_ASSERT(n_write == io_info->nwrite);
	EVUTIL_ASSERT(n_close == io_info->nclose);

	return 0;
}

void evmap_check_integrity_(struct event_base *base)
{
	evmap_io_foreach_fd(base, evmap_io_check_integrity_fn, NULL);
}

/* Helper type for evmap_foreach_event_: Bundles a function to call on every
 * event, and the user-provided void* to use as its third argument. */
struct evmap_foreach_event_helper
{
	event_base_foreach_event_cb fn;
	void *arg;
};

/* Helper for evmap_foreach_event_: calls a provided function on every event
 * pending on a given fd.  */
static int evmap_io_foreach_event_fn(struct event_base *base,
    evutil_socket_t fd, struct evmap_io *io_info, void *arg)
{
	struct evmap_foreach_event_helper *h = arg;
	struct event *ev;
	int r;
	LIST_FOREACH(ev, &io_info->events, ev_io_next)
    {
		if ((r = h->fn(base, ev, h->arg)))
			return r;
	}
	return 0;
}

int evmap_foreach_event_(
    struct event_base *base, event_base_foreach_event_cb fn, void *arg)
{
	struct evmap_foreach_event_helper h;
	h.fn = fn;
	h.arg = arg;

	return evmap_io_foreach_fd(base, evmap_io_foreach_event_fn, &h);
}

