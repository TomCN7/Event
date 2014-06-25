#include "stdafx.h"
#include "config.h"

#include "event-internal.h"
#include "changelist-internal.h"

/** Per-fd structure for use with changelists.  It keeps track, for each fd or
 * signal using the changelist, of where its entry in the changelist is.
 */
struct event_changelist_fdinfo
{
	int idxplus1; /* this is the index +1, so that memset(0) will make it a no-such-element */
};

void
event_changelist_init_(struct event_changelist *changelist)
{
	changelist->changes = NULL;
	changelist->changes_size = 0;
	changelist->n_changes = 0;
}

/** Helper: return the changelist_fdinfo corresponding to a given change. */
static inline struct event_changelist_fdinfo * event_change_get_fdinfo(
    struct event_base *base, const struct event_change *change)
{
	char *ptr;
	struct evmap_io *ctx;

	GET_IO_SLOT(ctx, &base->io, change->fd, evmap_io);
	ptr = ((char*)ctx) + sizeof(struct evmap_io);

    return (void*)ptr;
}

/** Callback helper for event_changelist_assert_ok */
static int event_changelist_assert_ok_foreach_iter_fn(
	struct event_base *base, evutil_socket_t fd, struct evmap_io *io, void *arg)
{
	struct event_changelist *changelist = &base->changelist;
	struct event_changelist_fdinfo *f;
	f = (void*)
	    ( ((char*)io) + sizeof(struct evmap_io) );
	if (f->idxplus1)
    {
		struct event_change *c = &changelist->changes[f->idxplus1 - 1];
		EVUTIL_ASSERT(c->fd == fd);
	}
	return 0;
}

/** Make sure that the changelist is consistent with the evmap structures. */
static void event_changelist_assert_ok(struct event_base *base)
{
	int i;
	struct event_changelist *changelist = &base->changelist;

	EVUTIL_ASSERT(changelist->changes_size >= changelist->n_changes);
	for (i = 0; i < changelist->n_changes; ++i)
    {
		struct event_change *c = &changelist->changes[i];
		struct event_changelist_fdinfo *f;
		EVUTIL_ASSERT(c->fd >= 0);
		f = event_change_get_fdinfo(base, c);
		EVUTIL_ASSERT(f);
		EVUTIL_ASSERT(f->idxplus1 == i + 1);
	}

	evmap_io_foreach_fd(
        base, event_changelist_assert_ok_foreach_iter_fn, NULL);
}

#ifdef DEBUG_CHANGELIST
#define event_changelist_check(base)  event_changelist_assert_ok((base))
#else
#define event_changelist_check(base)  ((void)0)
#endif

void event_changelist_remove_all_(
    struct event_changelist *changelist, struct event_base *base)
{
	int i;

	event_changelist_check(base);

	for (i = 0; i < changelist->n_changes; ++i)
    {
		struct event_change *ch = &changelist->changes[i];
		struct event_changelist_fdinfo *fdinfo =
		    event_change_get_fdinfo(base, ch);
		EVUTIL_ASSERT(fdinfo->idxplus1 == i + 1);
		fdinfo->idxplus1 = 0;
	}

	changelist->n_changes = 0;

	event_changelist_check(base);
}

void event_changelist_freemem_(struct event_changelist *changelist)
{
	if (changelist->changes)
		mm_free(changelist->changes);
	event_changelist_init_(changelist); /* zero it all out. */
}

/** Increase the size of 'changelist' to hold more changes. */
static int event_changelist_grow(struct event_changelist *changelist)
{
	int new_size;
	struct event_change *new_changes;
	if (changelist->changes_size < 64)
		new_size = 64;
	else
		new_size = changelist->changes_size * 2;

	new_changes = mm_realloc(changelist->changes,
	    new_size * sizeof(struct event_change));

	if (EVUTIL_UNLIKELY(new_changes == NULL))
		return (-1);

	changelist->changes = new_changes;
	changelist->changes_size = new_size;

	return (0);
}

/** Return a pointer to the changelist entry for the file descriptor or signal
 * 'fd', whose fdinfo is 'fdinfo'.  If none exists, construct it, setting its
 * old_events field to old_events.
 */
static struct event_change *
event_changelist_get_or_construct(struct event_changelist *changelist,
    evutil_socket_t fd, short old_events, struct event_changelist_fdinfo *fdinfo)
{
	struct event_change *change;

	if (fdinfo->idxplus1 == 0)
    {
		int idx;
		EVUTIL_ASSERT(changelist->n_changes <= changelist->changes_size);

		if (changelist->n_changes == changelist->changes_size)
        {
			if (event_changelist_grow(changelist) < 0)
				return NULL;
		}

		idx = changelist->n_changes++;
		change = &changelist->changes[idx];
		fdinfo->idxplus1 = idx + 1;

		memset(change, 0, sizeof(struct event_change));
		change->fd = fd;
		change->old_events = old_events;
	}
    else
    {
		change = &changelist->changes[fdinfo->idxplus1 - 1];
		EVUTIL_ASSERT(change->fd == fd);
	}
	return change;
}

int event_changelist_add_(struct event_base *base,
    evutil_socket_t fd, short old, short events, void *p)
{
	struct event_changelist *changelist = &base->changelist;
	struct event_changelist_fdinfo *fdinfo = p;
	struct event_change *change;

	event_changelist_check(base);

	change = event_changelist_get_or_construct(changelist, fd, old, fdinfo);
	if (!change)
		return -1;

	/* An add replaces any previous delete, but doesn't result in a no-op,
	 * since the delete might fail (because the fd had been closed since
	 * the last add, for instance. */

	if (events & (EV_READ))
		change->read_change  = EV_CHANGE_ADD | (events & (EV_ET|EV_PERSIST));

    if (events & EV_WRITE)
		change->write_change = EV_CHANGE_ADD | (events & (EV_ET|EV_PERSIST));

    if (events & EV_CLOSED)
		change->close_change = EV_CHANGE_ADD | (events & (EV_ET|EV_PERSIST));

	event_changelist_check(base);
	return (0);
}

int event_changelist_del_(struct event_base *base,
    evutil_socket_t fd, short old, short events, void *p)
{
	struct event_changelist *changelist = &base->changelist;
	struct event_changelist_fdinfo *fdinfo = p;
	struct event_change *change;

	event_changelist_check(base);

	change = event_changelist_get_or_construct(changelist, fd, old, fdinfo);
	event_changelist_check(base);
	if (!change)
		return -1;

	/* A delete on an event set that doesn't contain the event to be
	   deleted produces a no-op.  This effectively emoves any previous
	   uncommitted add, rather than replacing it: on those platforms where
	   "add, delete, dispatch" is not the same as "no-op, dispatch", we
	   want the no-op behavior.

	   If we have a no-op item, we could remove it it from the list
	   entirely, but really there's not much point: skipping the no-op
	   change when we do the dispatch later is far cheaper than rejuggling
	   the array now.

	   As this stands, it also lets through deletions of events that are
	   not currently set.
	 */

	if (events & (EV_READ))
    {
		if (!(change->old_events & EV_READ))
			change->read_change = 0;
		else
			change->read_change = EV_CHANGE_DEL;
	}
	if (events & EV_WRITE)
    {
		if (!(change->old_events & EV_WRITE))
			change->write_change = 0;
		else
			change->write_change = EV_CHANGE_DEL;
	}
	if (events & EV_CLOSED)
    {
		if (!(change->old_events & EV_CLOSED))
			change->close_change = 0;
		else
			change->close_change = EV_CHANGE_DEL;
	}

	event_changelist_check(base);
	return (0);
}