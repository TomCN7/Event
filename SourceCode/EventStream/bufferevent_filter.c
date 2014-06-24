/*
 * Copyright (c) 2007-2012 Niels Provos and Nick Mathewson
 * Copyright (c) 2002-2006 Niels Provos <provos@citi.umich.edu>
 * All rights reserved.
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

#include "util.h"
#include "bufferevent.h"
#include "buffer.h"
#include "bufferevent_struct.h"
#include "event.h"
#include "log-internal.h"
#include "mm-internal.h"
#include "bufferevent-internal.h"
#include "util-internal.h"

/* prototypes */
static int be_filter_enable(struct bufferevent *, short);
static int be_filter_disable(struct bufferevent *, short);
static void be_filter_unlink(struct bufferevent *);
static void be_filter_destruct(struct bufferevent *);

static void be_filter_readcb(struct bufferevent *, void *);
static void be_filter_writecb(struct bufferevent *, void *);
static void be_filter_eventcb(struct bufferevent *, short, void *);
static int be_filter_flush(
    struct bufferevent *bufev, short iotype, enum bufferevent_flush_mode mode);
static int be_filter_ctrl(
    struct bufferevent *, enum bufferevent_ctrl_op, union bufferevent_ctrl_data *);

static void bufferevent_filtered_outbuf_cb(
    struct evbuffer *buf, const struct evbuffer_cb_info *info, void *arg);

struct bufferevent_filtered
{
	struct bufferevent_private bev;

	/** The bufferevent that we read/write filtered data from/to. */
	struct bufferevent *underlying;
	/** A callback on our outbuf to notice when somebody adds data */
	struct evbuffer_cb_entry *outbuf_cb;
	/** True iff we have received an EOF callback from the underlying
	 * bufferevent. */
	unsigned got_eof;

	/** Function to free context when we're done. */
	void (*free_context)(void *);
	/** Input filter */
	bufferevent_filter_cb process_in;
	/** Output filter */
	bufferevent_filter_cb process_out;
	/** User-supplied argument to the filters. */
	void *context;
};

const struct bufferevent_ops bufferevent_ops_filter = 
{
	"filter",
	evutil_offsetof(struct bufferevent_filtered, bev.bev),
	be_filter_enable,
	be_filter_disable,
	be_filter_unlink,
	be_filter_destruct,
	bufferevent_generic_adj_timeouts_,
	be_filter_flush,
	be_filter_ctrl,
};

/* Given a bufferevent that's really the bev filter of a bufferevent_filtered,
 * return that bufferevent_filtered. Returns NULL otherwise.*/
static inline struct bufferevent_filtered * upcast(struct bufferevent *bev)
{
	struct bufferevent_filtered *bev_f;
	if (bev->be_ops != &bufferevent_ops_filter)
		return NULL;
	bev_f = (void*)( ((char*)bev) -
			 evutil_offsetof(struct bufferevent_filtered, bev.bev));
	EVUTIL_ASSERT(bev_f->bev.bev.be_ops == &bufferevent_ops_filter);
	return bev_f;
}

#define downcast(bev_f) (&(bev_f)->bev.bev)

/* Filter to use when we're created with a NULL filter. */
static enum bufferevent_filter_result
be_null_filter(struct evbuffer *src, struct evbuffer *dst, 
    ev_ssize_t lim, enum bufferevent_flush_mode state, void *ctx)
{
	(void)state;
	if (evbuffer_remove_buffer(src, dst, lim) == 0)
		return BEV_OK;
	else
		return BEV_ERROR;
}

struct bufferevent * bufferevent_filter_new(
    struct bufferevent *underlying, bufferevent_filter_cb input_filter, 
    bufferevent_filter_cb output_filter, int options,
    void (*free_context)(void *), void *ctx)
{
	struct bufferevent_filtered *bufev_f;
	int tmp_options = options;

	if (!underlying)
		return NULL;

	if (!input_filter)
		input_filter = be_null_filter;
	if (!output_filter)
		output_filter = be_null_filter;

	bufev_f = mm_calloc(1, sizeof(struct bufferevent_filtered));
	if (!bufev_f)
		return NULL;

	if (bufferevent_init_common_(&bufev_f->bev, underlying->ev_base,
				    &bufferevent_ops_filter, tmp_options) < 0)
    {
		mm_free(bufev_f);
		return NULL;
	}

	bufev_f->underlying = underlying;

	bufev_f->process_in = input_filter;
	bufev_f->process_out = output_filter;
	bufev_f->free_context = free_context;
	bufev_f->context = ctx;

	bufferevent_setcb(bufev_f->underlying,
	    be_filter_readcb, be_filter_writecb, be_filter_eventcb, bufev_f);

	bufev_f->outbuf_cb = evbuffer_add_cb(downcast(bufev_f)->output,
	   bufferevent_filtered_outbuf_cb, bufev_f);

	bufferevent_init_generic_timeout_cbs_(downcast(bufev_f));
	bufferevent_incref_(underlying);

	bufferevent_enable(underlying, EV_READ|EV_WRITE);
	bufferevent_suspend_read_(underlying, BEV_SUSPEND_FILT_READ);

	return downcast(bufev_f);
}

static void be_filter_unlink(struct bufferevent *bev)
{
	struct bufferevent_filtered *bevf = upcast(bev);
	EVUTIL_ASSERT(bevf);

	if (bevf->bev.options & BEV_OPT_CLOSE_ON_FREE)
    {
		/* Yes, there is also a decref in bufferevent_decref_.
		 * That decref corresponds to the incref when we set
		 * underlying for the first time.  This decref is an
		 * extra one to remove the last reference.
		 */
		if (BEV_UPCAST(bevf->underlying)->refcnt < 2) {
			event_warnx("BEV_OPT_CLOSE_ON_FREE set on an "
			    "bufferevent with too few references");
		} else {
			bufferevent_free(bevf->underlying);
		}
	}
    else
    {
		if (bevf->underlying)
        {
			if (bevf->underlying->errorcb == be_filter_eventcb)
				bufferevent_setcb(bevf->underlying, NULL, NULL, NULL, NULL);
			bufferevent_unsuspend_read_(bevf->underlying, BEV_SUSPEND_FILT_READ);
		}
	}
}

static void be_filter_destruct(struct bufferevent *bev)
{
	struct bufferevent_filtered *bevf = upcast(bev);
	EVUTIL_ASSERT(bevf);
	if (bevf->free_context)
		bevf->free_context(bevf->context);
}

static int be_filter_enable(struct bufferevent *bev, short event)
{
	struct bufferevent_filtered *bevf = upcast(bev);
	if (event & EV_WRITE)
		BEV_RESET_GENERIC_WRITE_TIMEOUT(bev);

	if (event & EV_READ)
    {
		BEV_RESET_GENERIC_READ_TIMEOUT(bev);
		bufferevent_unsuspend_read_(bevf->underlying, BEV_SUSPEND_FILT_READ);
	}
	return 0;
}

static int be_filter_disable(struct bufferevent *bev, short event)
{
	struct bufferevent_filtered *bevf = upcast(bev);
	if (event & EV_WRITE)
		BEV_DEL_GENERIC_WRITE_TIMEOUT(bev);

	if (event & EV_READ)
    {
		BEV_DEL_GENERIC_READ_TIMEOUT(bev);
		bufferevent_suspend_read_(bevf->underlying, BEV_SUSPEND_FILT_READ);
	}
	return 0;
}

static enum bufferevent_filter_result be_filter_process_input(
    struct bufferevent_filtered *bevf, enum bufferevent_flush_mode state, int *processed_out)
{
	enum bufferevent_filter_result res;
	struct bufferevent *bev = downcast(bevf);

	/* If we're in 'normal' mode, don't urge data on the filter
	 * unless we're reading data*/
    if (state == BEV_NORMAL && !(bev->enabled & EV_READ))
		return BEV_OK;

	do
    {
		ev_ssize_t limit = -1;

		res = bevf->process_in(
            bevf->underlying->input, bev->input, limit, state, bevf->context);

		if (res == BEV_OK)
			*processed_out = 1;
	}
    while (res == BEV_OK && (bev->enabled & EV_READ) && evbuffer_get_length(bevf->underlying->input));

	if (*processed_out)
		BEV_RESET_GENERIC_READ_TIMEOUT(bev);

	return res;
}


static enum bufferevent_filter_result
be_filter_process_output(struct bufferevent_filtered *bevf,
			 enum bufferevent_flush_mode state, int *processed_out)
{
	/* Requires references and lock: might call writecb */
	enum bufferevent_filter_result res = BEV_OK;
	struct bufferevent *bufev = downcast(bevf);
	int again = 0;

	if (state == BEV_NORMAL) {
		/* If we're in 'normal' mode, don't urge data on the
		 * filter unless we're writing data, and the underlying
		 * bufferevent is accepting data, and we have data to
		 * give the filter.  If we're in 'flush' or 'finish',
		 * call the filter no matter what. */
		if (!(bufev->enabled & EV_WRITE) || !evbuffer_get_length(bufev->output))
			return BEV_OK;
	}

	/* disable the callback that calls this function
	   when the user adds to the output buffer. */
	evbuffer_cb_set_flags(bufev->output, bevf->outbuf_cb, 0);

	do {
		int processed = 0;
		again = 0;

		do {
			ev_ssize_t limit = -1;

			res = bevf->process_out(downcast(bevf)->output,
			    bevf->underlying->output, limit, state, bevf->context);

			if (res == BEV_OK)
				processed = *processed_out = 1;
		} while (/* Stop if the filter wasn't successful...*/
			res == BEV_OK &&
			/* Or if we aren't writing any more. */
			(bufev->enabled & EV_WRITE) &&
			/* Of if we have nothing more to write and we are
			 * not flushing. */
			evbuffer_get_length(bufev->output));

		if (processed) {
			/* call the write callback.*/
			bufferevent_trigger_io(bufev, EV_WRITE, 0);

			if (res == BEV_OK && (bufev->enabled & EV_WRITE) && evbuffer_get_length(bufev->output))
				again = 1;
		}
	} while (again);

	/* reenable the outbuf_cb */
	evbuffer_cb_set_flags(bufev->output,bevf->outbuf_cb,
	    EVBUFFER_CB_ENABLED);

	if (*processed_out)
		BEV_RESET_GENERIC_WRITE_TIMEOUT(bufev);

	return res;
}

/* Called when the size of our outbuf changes. */
static void
bufferevent_filtered_outbuf_cb(struct evbuffer *buf,
    const struct evbuffer_cb_info *cbinfo, void *arg)
{
	struct bufferevent_filtered *bevf = arg;
	struct bufferevent *bev = downcast(bevf);

	if (cbinfo->n_added) {
		int processed_any = 0;
		/* Somebody added more data to the output buffer. Try to
		 * process it, if we should. */
		bufferevent_incref(bev);
		be_filter_process_output(bevf, BEV_NORMAL, &processed_any);
		bufferevent_decref(bev);
	}
}

/* Called when the underlying socket has read. */
static void
be_filter_readcb(struct bufferevent *underlying, void *me_)
{
	struct bufferevent_filtered *bevf = me_;
	enum bufferevent_filter_result res;
	enum bufferevent_flush_mode state;
	struct bufferevent *bufev = downcast(bevf);
	int processed_any = 0;

	bufferevent_incref(bufev);

	if (bevf->got_eof)
		state = BEV_FINISHED;
	else
		state = BEV_NORMAL;

	/* XXXX use return value */
	res = be_filter_process_input(bevf, state, &processed_any);
	(void)res;

	/* XXX This should be in process_input, not here.  There are
	 * other places that can call process-input, and they should
	 * force readcb calls as needed. */
	if (processed_any)
		bufferevent_trigger_io(bufev, EV_READ, 0);

	bufferevent_decref(bufev);
}

/* Called when the underlying socket has drained enough that we can write to
   it. */
static void
be_filter_writecb(struct bufferevent *underlying, void *me_)
{
	struct bufferevent_filtered *bevf = me_;
	struct bufferevent *bev = downcast(bevf);
	int processed_any = 0;

	bufferevent_incref(bev);
	be_filter_process_output(bevf, BEV_NORMAL, &processed_any);
	bufferevent_decref(bev);
}

/* Called when the underlying socket has given us an error */
static void
be_filter_eventcb(struct bufferevent *underlying, short what, void *me_)
{
	struct bufferevent_filtered *bevf = me_;
	struct bufferevent *bev = downcast(bevf);

	bufferevent_incref(bev);
	/* All we can really to is tell our own eventcb. */
	bufferevent_run_eventcb_(bev, what, 0);
	bufferevent_decref(bev);
}

static int
be_filter_flush(struct bufferevent *bufev,
    short iotype, enum bufferevent_flush_mode mode)
{
	struct bufferevent_filtered *bevf = upcast(bufev);
	int processed_any = 0;
	EVUTIL_ASSERT(bevf);

	bufferevent_incref(bufev);

	if (iotype & EV_READ) {
		be_filter_process_input(bevf, mode, &processed_any);
	}
	if (iotype & EV_WRITE) {
		be_filter_process_output(bevf, mode, &processed_any);
	}
	/* XXX check the return value? */
	/* XXX does this want to recursively call lower-level flushes? */
	bufferevent_flush(bevf->underlying, iotype, mode);

	bufferevent_decref(bufev);

	return processed_any;
}

static int
be_filter_ctrl(struct bufferevent *bev, enum bufferevent_ctrl_op op,
    union bufferevent_ctrl_data *data)
{
	struct bufferevent_filtered *bevf;
	switch (op)
    {
	case BEV_CTRL_GET_UNDERLYING:
		bevf = upcast(bev);
		data->ptr = bevf->underlying;
		return 0;
	case BEV_CTRL_GET_FD:
	case BEV_CTRL_SET_FD:
	case BEV_CTRL_CANCEL_ALL:
	default:
		return -1;
	}
}