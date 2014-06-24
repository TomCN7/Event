/*
 * Copyright (c) 2002-2007 Niels Provos <provos@citi.umich.edu>
 * Copyright (c) 2007-2012 Niels Provos, Nick Mathewson
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

#include <sys/types.h>

#ifdef EVENT__HAVE_SYS_TIME_H
#include <sys/time.h>
#endif

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef EVENT__HAVE_STDARG_H
#include <stdarg.h>
#endif

#ifdef _WIN32
#include <winsock2.h>
#endif
#include <errno.h>

#include "util.h"
#include "buffer.h"
#include "bufferevent.h"
#include "bufferevent_struct.h"
#include "event.h"
#include "event-internal.h"
#include "log-internal.h"
#include "mm-internal.h"
#include "bufferevent-internal.h"
#include "evbuffer-internal.h"
#include "util-internal.h"

static void bufferevent_cancel_all_(struct bufferevent *bev);
static void bufferevent_finalize_cb_(struct event_callback *evcb, void *arg_);

void bufferevent_suspend_read_(
    struct bufferevent *bufev, bufferevent_suspend_flags what)
{
	struct bufferevent_private *bufev_private =
	    EVUTIL_UPCAST(bufev, struct bufferevent_private, bev);

    if (!bufev_private->read_suspended)
		bufev->be_ops->disable(bufev, EV_READ);
	bufev_private->read_suspended |= what;
}

void bufferevent_unsuspend_read_(
    struct bufferevent *bufev, bufferevent_suspend_flags what)
{
	struct bufferevent_private *bufev_private =
	    EVUTIL_UPCAST(bufev, struct bufferevent_private, bev);

    bufev_private->read_suspended &= ~what;
	if (!bufev_private->read_suspended && (bufev->enabled & EV_READ))
		bufev->be_ops->enable(bufev, EV_READ);
}

void bufferevent_suspend_write_(
    struct bufferevent *bufev, bufferevent_suspend_flags what)
{
	struct bufferevent_private *bufev_private =
	    EVUTIL_UPCAST(bufev, struct bufferevent_private, bev);

    if (!bufev_private->write_suspended)
		bufev->be_ops->disable(bufev, EV_WRITE);
	bufev_private->write_suspended |= what;
}

void bufferevent_unsuspend_write_(
    struct bufferevent *bufev, bufferevent_suspend_flags what)
{
	struct bufferevent_private *bufev_private =
	    EVUTIL_UPCAST(bufev, struct bufferevent_private, bev);

    bufev_private->write_suspended &= ~what;
	if (!bufev_private->write_suspended && (bufev->enabled & EV_WRITE))
		bufev->be_ops->enable(bufev, EV_WRITE);
}

static void
bufferevent_run_deferred_callbacks(struct event_callback *cb, void *arg)
{
	struct bufferevent_private *bufev_private = arg;
	struct bufferevent *bufev = &bufev_private->bev;

	if ((bufev_private->eventcb_pending & BEV_EVENT_CONNECTED) && bufev->errorcb)
    {
	/* The "connected" happened before any reads or writes, so send it first. */
		bufev_private->eventcb_pending &= ~BEV_EVENT_CONNECTED;
		bufev->errorcb(bufev, BEV_EVENT_CONNECTED, bufev->cbarg);
	}
	if (bufev_private->readcb_pending && bufev->readcb)
    {
		bufev_private->readcb_pending = 0;
		bufev->readcb(bufev, bufev->cbarg);
	}
	if (bufev_private->writecb_pending && bufev->writecb)
    {
		bufev_private->writecb_pending = 0;
		bufev->writecb(bufev, bufev->cbarg);
	}
	if (bufev_private->eventcb_pending && bufev->errorcb)
    {
		short what = bufev_private->eventcb_pending;
		int err = bufev_private->errno_pending;
		bufev_private->eventcb_pending = 0;
		bufev_private->errno_pending = 0;
		EVUTIL_SET_SOCKET_ERROR(err);
		bufev->errorcb(bufev, what, bufev->cbarg);
	}
	bufferevent_decref(bufev);
}

#define SCHEDULE_DEFERRED(bevp)			\
	do {								\
		if (event_deferred_cb_schedule_((bevp)->bev.ev_base, &(bevp)->deferred)) \
			bufferevent_incref_(&(bevp)->bev); \
	} while (0)


void bufferevent_run_readcb_(struct bufferevent *bufev, int options)
{
	/* Requires that we hold the lock and a reference */
	struct bufferevent_private *p =
	    EVUTIL_UPCAST(bufev, struct bufferevent_private, bev);
	if (bufev->readcb == NULL)
		return;

	if ((p->options|options) & BEV_OPT_DEFER_CALLBACKS) 
    {
		p->readcb_pending = 1;
		SCHEDULE_DEFERRED(p);
	}
    else
    {
		bufev->readcb(bufev, bufev->cbarg);
	}
}

void bufferevent_run_writecb_(struct bufferevent *bufev, int options)
{
	/* Requires that we hold the lock and a reference */
	struct bufferevent_private *p =
	    EVUTIL_UPCAST(bufev, struct bufferevent_private, bev);
	if (bufev->writecb == NULL)
		return;

	if ((p->options|options) & BEV_OPT_DEFER_CALLBACKS) 
    {
		p->writecb_pending = 1;
		SCHEDULE_DEFERRED(p);
	}
    else
    {
		bufev->writecb(bufev, bufev->cbarg);
	}
}

void bufferevent_trigger_io(struct bufferevent *bufev, short iotype, int options)
{
	bufferevent_incref(bufev);

    if (iotype & EV_READ)
        bufferevent_run_readcb_(bufev, options);

    if (iotype & EV_WRITE)
        bufferevent_run_writecb_(bufev, options);

    bufferevent_decref(bufev);
}

void bufferevent_run_eventcb_(struct bufferevent *bufev, short what, int options)
{
	/* Requires that we hold the lock and a reference */
	struct bufferevent_private *p =
	    EVUTIL_UPCAST(bufev, struct bufferevent_private, bev);
	if (bufev->errorcb == NULL)
		return;

	if ((p->options|options) & BEV_OPT_DEFER_CALLBACKS)
    {
		p->eventcb_pending |= what;
		p->errno_pending = EVUTIL_SOCKET_ERROR();
		SCHEDULE_DEFERRED(p);
	}
    else
    {
		bufev->errorcb(bufev, what, bufev->cbarg);
	}
}

void bufferevent_trigger_event(struct bufferevent *bufev, short what, int options)
{
	bufferevent_incref(bufev);

    bufferevent_run_eventcb_(bufev, what, options);

	bufferevent_decref(bufev);
}

int bufferevent_init_common_(struct bufferevent_private *bufev_private,
    struct event_base *base, const struct bufferevent_ops *ops,
    enum bufferevent_options options)
{
	struct bufferevent *bufev = &bufev_private->bev;

	if (!bufev->input) 
    {
		if ((bufev->input = evbuffer_new()) == NULL)
			return -1;
	}

	if (!bufev->output) 
    {
		if ((bufev->output = evbuffer_new()) == NULL) 
        {
			evbuffer_free(bufev->input);
			return -1;
		}
	}

	bufev_private->refcnt = 1;
	bufev->ev_base = base;

	/* Disable timeouts. */
	evutil_timerclear(&bufev->timeout_read);
	evutil_timerclear(&bufev->timeout_write);

	bufev->be_ops = ops;

	/*
	 * Set to EV_WRITE so that using bufferevent_write is going to
	 * trigger a callback.  Reading needs to be explicitly enabled
	 * because otherwise no data will be available.
	 */
	bufev->enabled = EV_WRITE;

    event_deferred_cb_init_(
        &bufev_private->deferred, event_base_get_npriorities(base) / 2,
        bufferevent_run_deferred_callbacks, bufev_private);

	bufev_private->options = options;

	evbuffer_set_parent_(bufev->input, bufev);
	evbuffer_set_parent_(bufev->output, bufev);

	return 0;
}

void bufferevent_setcb(struct bufferevent *bufev,
    bufferevent_data_cb readcb, bufferevent_data_cb writecb,
    bufferevent_event_cb eventcb, void *cbarg)
{
	bufev->readcb = readcb;
	bufev->writecb = writecb;
	bufev->errorcb = eventcb;

	bufev->cbarg = cbarg;
}

void bufferevent_getcb(struct bufferevent *bufev,
    bufferevent_data_cb *readcb_ptr, bufferevent_data_cb *writecb_ptr,
    bufferevent_event_cb *eventcb_ptr, void **cbarg_ptr)
{
	if (readcb_ptr)
		*readcb_ptr = bufev->readcb;
	if (writecb_ptr)
		*writecb_ptr = bufev->writecb;
	if (eventcb_ptr)
		*eventcb_ptr = bufev->errorcb;
	if (cbarg_ptr)
		*cbarg_ptr = bufev->cbarg;
}

struct evbuffer* bufferevent_get_input(struct bufferevent *bufev)
{
	return bufev->input;
}

struct evbuffer* bufferevent_get_output(struct bufferevent *bufev)
{
	return bufev->output;
}

struct event_base* bufferevent_get_base(struct bufferevent *bufev)
{
	return bufev->ev_base;
}

int bufferevent_get_priority(const struct bufferevent *bufev)
{
	if (event_initialized(&bufev->ev_read))
		return event_get_priority(&bufev->ev_read);
	
    return event_base_get_npriorities(bufev->ev_base) / 2;
}

int bufferevent_write(struct bufferevent *bufev, const void *data, size_t size)
{
	if (evbuffer_add(bufev->output, data, size) == -1)
		return (-1);

	return 0;
}

int bufferevent_write_buffer(struct bufferevent *bufev, struct evbuffer *buf)
{
	if (evbuffer_add_buffer(bufev->output, buf) == -1)
		return (-1);

	return 0;
}

size_t bufferevent_read(struct bufferevent *bufev, void *data, size_t size)
{
	return (evbuffer_remove(bufev->input, data, size));
}

int bufferevent_read_buffer(struct bufferevent *bufev, struct evbuffer *buf)
{
	return (evbuffer_add_buffer(buf, bufev->input));
}

int bufferevent_enable(struct bufferevent *bufev, short event)
{
	struct bufferevent_private *bufev_private =
	    EVUTIL_UPCAST(bufev, struct bufferevent_private, bev);
	short impl_events = event;
	int r = 0;

	bufferevent_incref(bufev);
	if (bufev_private->read_suspended)
		impl_events &= ~EV_READ;
	if (bufev_private->write_suspended)
		impl_events &= ~EV_WRITE;

	bufev->enabled |= event;

	if (impl_events && bufev->be_ops->enable(bufev, impl_events) < 0)
		r = -1;

	bufferevent_decref(bufev);
	return r;
}

int bufferevent_set_timeouts(struct bufferevent *bufev,
    const struct timeval *tv_read, const struct timeval *tv_write)
{
	int r = 0;

    if (tv_read)
		bufev->timeout_read = *tv_read;
	else
		evutil_timerclear(&bufev->timeout_read);

    if (tv_write)
		bufev->timeout_write = *tv_write;
	else
		evutil_timerclear(&bufev->timeout_write);

	if (bufev->be_ops->adj_timeouts)
		r = bufev->be_ops->adj_timeouts(bufev);

	return r;
}

int bufferevent_disable_hard_(struct bufferevent *bufev, short event)
{
	int r = 0;
	struct bufferevent_private *bufev_private =
	    EVUTIL_UPCAST(bufev, struct bufferevent_private, bev);

	bufev->enabled &= ~event;

	bufev_private->connecting = 0;
	if (bufev->be_ops->disable(bufev, event) < 0)
		r = -1;

	return r;
}

int bufferevent_disable(struct bufferevent *bufev, short event)
{
	int r = 0;

	bufev->enabled &= ~event;

	if (bufev->be_ops->disable(bufev, event) < 0)
		r = -1;

	return r;
}

int bufferevent_flush(
    struct bufferevent *bufev, short iotype, enum bufferevent_flush_mode mode)
{
	int r = -1;

    if (bufev->be_ops->flush)
		r = bufev->be_ops->flush(bufev, iotype, mode);

    return r;
}

void bufferevent_incref(struct bufferevent *bufev)
{
	struct bufferevent_private *bufev_private = BEV_UPCAST(bufev);
	++bufev_private->refcnt;
}

int bufferevent_decref(struct bufferevent *bufev)
{
	struct bufferevent_private *bufev_private =
	    EVUTIL_UPCAST(bufev, struct bufferevent_private, bev);
	int n_cbs = 0;
#define MAX_CBS 16
	struct event_callback *cbs[MAX_CBS];

	EVUTIL_ASSERT(bufev_private->refcnt > 0);

	if (--bufev_private->refcnt)
		return 0;

	if (bufev->be_ops->unlink)
		bufev->be_ops->unlink(bufev);

	/* Okay, we're out of references. Let's finalize this once all the
	 * callbacks are done running. */
	cbs[0] = &bufev->ev_read.ev_evcallback;
	cbs[1] = &bufev->ev_write.ev_evcallback;
	cbs[2] = &bufev_private->deferred;
	n_cbs = 3;
	n_cbs += evbuffer_get_callbacks_(bufev->input, cbs+n_cbs, MAX_CBS-n_cbs);
	n_cbs += evbuffer_get_callbacks_(bufev->output, cbs+n_cbs, MAX_CBS-n_cbs);

	event_callback_finalize_many_(
        bufev->ev_base, n_cbs, cbs, bufferevent_finalize_cb_);

#undef MAX_CBS
	return 1;
}

static void bufferevent_finalize_cb_(struct event_callback *evcb, void *arg_)
{
	struct bufferevent *bufev = arg_;
	struct bufferevent *underlying;
	struct bufferevent_private *bufev_private =
	    EVUTIL_UPCAST(bufev, struct bufferevent_private, bev);

	underlying = bufferevent_get_underlying(bufev);

	/* Clean up the shared info */
	if (bufev->be_ops->destruct)
		bufev->be_ops->destruct(bufev);

	/* XXX what happens if refcnt for these buffers is > 1?
	 * The buffers can share a lock with this bufferevent object,
	 * but the lock might be destroyed below. */
	/* evbuffer will free the callbacks */
	evbuffer_free(bufev->input);
	evbuffer_free(bufev->output);

	/* Free the actual allocated memory. */
	mm_free(((char*)bufev) - bufev->be_ops->mem_offset);

	/* Release the reference to underlying now that we no longer need the
	 * reference to it.  We wait this long mainly in case our lock is
	 * shared with underlying.
	 *
	 * The 'destruct' function will also drop a reference to underlying
	 * if BEV_OPT_CLOSE_ON_FREE is set.
	 *
	 * XXX Should we/can we just refcount evbuffer/bufferevent locks?
	 * It would probably save us some headaches.
	 */
	if (underlying)
		bufferevent_decref(underlying);
}

void bufferevent_free(struct bufferevent *bufev)
{
	bufferevent_setcb(bufev, NULL, NULL, NULL, NULL);
	bufferevent_cancel_all_(bufev);
	bufferevent_decref(bufev);
}

void bufferevent_incref_(struct bufferevent *bufev)
{
	struct bufferevent_private *bufev_private =
	    EVUTIL_UPCAST(bufev, struct bufferevent_private, bev);

	++bufev_private->refcnt;
}

int bufferevent_setfd(struct bufferevent *bev, evutil_socket_t fd)
{
	union bufferevent_ctrl_data d;
	int res = -1;

    d.fd = fd;
	if (bev->be_ops->ctrl)
		res = bev->be_ops->ctrl(bev, BEV_CTRL_SET_FD, &d);

    return res;
}

evutil_socket_t bufferevent_getfd(struct bufferevent *bev)
{
	union bufferevent_ctrl_data d;
	int res = -1;

    d.fd = -1;
	if (bev->be_ops->ctrl)
		res = bev->be_ops->ctrl(bev, BEV_CTRL_GET_FD, &d);

    return (res<0) ? -1 : d.fd;
}

enum bufferevent_options bufferevent_get_options_(struct bufferevent *bev)
{
	struct bufferevent_private *bev_p =
	    EVUTIL_UPCAST(bev, struct bufferevent_private, bev);
	enum bufferevent_options options;

	options = bev_p->options;

    return options;
}

static void bufferevent_cancel_all_(struct bufferevent *bev)
{
	union bufferevent_ctrl_data d;
	memset(&d, 0, sizeof(d));
	if (bev->be_ops->ctrl)
		bev->be_ops->ctrl(bev, BEV_CTRL_CANCEL_ALL, &d);
}

short bufferevent_get_enabled(struct bufferevent *bufev)
{
	return bufev->enabled;
}

struct bufferevent * bufferevent_get_underlying(struct bufferevent *bev)
{
	union bufferevent_ctrl_data d;
	int res = -1;
	d.ptr = NULL;
	if (bev->be_ops->ctrl)
		res = bev->be_ops->ctrl(bev, BEV_CTRL_GET_UNDERLYING, &d);
	return (res<0) ? NULL : d.ptr;
}

static void
bufferevent_generic_read_timeout_cb(evutil_socket_t fd, short event, void *ctx)
{
	struct bufferevent *bev = ctx;
	bufferevent_incref(bev);
	bufferevent_disable(bev, EV_READ);
	bufferevent_run_eventcb_(bev, BEV_EVENT_TIMEOUT|BEV_EVENT_READING, 0);
	bufferevent_decref(bev);
}
static void
bufferevent_generic_write_timeout_cb(evutil_socket_t fd, short event, void *ctx)
{
	struct bufferevent *bev = ctx;
	bufferevent_incref(bev);
	bufferevent_disable(bev, EV_WRITE);
	bufferevent_run_eventcb_(bev, BEV_EVENT_TIMEOUT|BEV_EVENT_WRITING, 0);
	bufferevent_decref(bev);
}

void bufferevent_init_generic_timeout_cbs_(struct bufferevent *bev)
{
	event_assign(&bev->ev_read, bev->ev_base, -1, EV_FINALIZE,
	    bufferevent_generic_read_timeout_cb, bev);
	event_assign(&bev->ev_write, bev->ev_base, -1, EV_FINALIZE,
	    bufferevent_generic_write_timeout_cb, bev);
}

int bufferevent_generic_adj_timeouts_(struct bufferevent *bev)
{
	const short enabled = bev->enabled;
	struct bufferevent_private *bev_p =
	    EVUTIL_UPCAST(bev, struct bufferevent_private, bev);
	int r1=0, r2=0;
	if ((enabled & EV_READ) && !bev_p->read_suspended && evutil_timerisset(&bev->timeout_read))
		r1 = event_add(&bev->ev_read, &bev->timeout_read, 0);
	else
		r1 = event_del_general(&bev->ev_read);

	if ((enabled & EV_WRITE) && !bev_p->write_suspended &&
	    evutil_timerisset(&bev->timeout_write) &&
	    evbuffer_get_length(bev->output))
		r2 = event_add(&bev->ev_write, &bev->timeout_write, 0);
	else
		r2 = event_del_general(&bev->ev_write);
	if (r1 < 0 || r2 < 0)
		return -1;
	return 0;
}

int bufferevent_add_event_(struct event *ev, const struct timeval *tv)
{
	if (tv->tv_sec == 0 && tv->tv_usec == 0)
		return event_add(ev, NULL, 0);
	else
		return event_add(ev, tv, 0);
}
