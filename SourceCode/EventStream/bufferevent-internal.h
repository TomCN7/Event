/*
 * Copyright (c) 2008-2012 Niels Provos and Nick Mathewson
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
#ifndef BUFFEREVENT_INTERNAL_H_INCLUDED_
#define BUFFEREVENT_INTERNAL_H_INCLUDED_

#ifdef __cplusplus
extern "C" {
#endif

#include "config.h"
#include "event_struct.h"
#include "util.h"
#include "util-internal.h"
#include "defer-internal.h"
#include "bufferevent_struct.h"

/* These flags are reasons that we might be declining to actually enable
   reading or writing on a bufferevent.
 */

/* On a socket bufferevent: can't do any operations while we're waiting for
 * name lookup to finish. */
#define BEV_SUSPEND_LOOKUP 0x01
/* On a base bufferevent, for reading: used when a filter has choked this
 * (underlying) bufferevent because it has stopped reading from it. */
#define BEV_SUSPEND_FILT_READ 0x02

typedef uint16_t bufferevent_suspend_flags;

/** Parts of the bufferevent structure that are shared among all bufferevent
 * types, but not exposed in bufferevent_struct.h. */
struct bufferevent_private 
{
	/** The underlying bufferevent structure. */
	struct bufferevent bev;

	/** Flag: set if we have deferred callbacks and a read callback is
	 * pending. */
	unsigned readcb_pending : 1;
	/** Flag: set if we have deferred callbacks and a write callback is
	 * pending. */
	unsigned writecb_pending : 1;
	/** Flag: set if we are currently busy connecting. */
	unsigned connecting : 1;
	/** Flag: set if a connect failed prematurely; this is a hack for
	 * getting around the bufferevent abstraction. */
	unsigned connection_refused : 1;
	/** Set to the events pending if we have deferred callbacks and
	 * an events callback is pending. */
	short eventcb_pending;

	/** If set, read is suspended until one or more conditions are over.
	 * The actual value here is a bitfield of those conditions; see the
	 * BEV_SUSPEND_* flags above. */
	bufferevent_suspend_flags read_suspended;

	/** If set, writing is suspended until one or more conditions are over.
	 * The actual value here is a bitfield of those conditions; see the
	 * BEV_SUSPEND_* flags above. */
	bufferevent_suspend_flags write_suspended;

	/** Set to the current socket errno if we have deferred callbacks and
	 * an events callback is pending. */
	int errno_pending;

	/** The DNS error code for bufferevent_socket_connect_hostname */
	int dns_error;

	/** Used to implement deferred callbacks */
	struct event_callback deferred;

	/** The options this bufferevent was constructed with */
	enum bufferevent_options options;

	/** Current reference count for this bufferevent. */
	int refcnt;
};

/** Possible operations for a control callback. */
enum bufferevent_ctrl_op 
{
	BEV_CTRL_SET_FD,
	BEV_CTRL_GET_FD,
	BEV_CTRL_GET_UNDERLYING,
	BEV_CTRL_CANCEL_ALL
};

/** Possible data types for a control callback */
union bufferevent_ctrl_data 
{
	void *ptr;
	evutil_socket_t fd;
};

/**
   Implementation table for a bufferevent: holds function pointers and other
   information to make the various bufferevent types work.
*/
struct bufferevent_ops 
{
	/** The name of the bufferevent's type. */
	const char *type;
	/** At what offset into the implementation type will we find a
	    bufferevent structure?

	    Example: if the type is implemented as
	    struct bufferevent_x {
	       int extra_data;
	       struct bufferevent bev;
	    }
	    then mem_offset should be offsetof(struct bufferevent_x, bev)
	*/
	off_t mem_offset;

	/** Enables one or more of EV_READ|EV_WRITE on a bufferevent.  Does
	    not need to adjust the 'enabled' field.  Returns 0 on success, -1
	    on failure.
	 */
	int (*enable)(struct bufferevent *, short);

	/** Disables one or more of EV_READ|EV_WRITE on a bufferevent.  Does
	    not need to adjust the 'enabled' field.  Returns 0 on success, -1
	    on failure.
	 */
	int (*disable)(struct bufferevent *, short);

	/** Detatches the bufferevent from related data structures. Called as
	 * soon as its reference count reaches 0. */
	void (*unlink)(struct bufferevent *);

	/** Free any storage and deallocate any extra data or structures used
	    in this implementation. Called when the bufferevent is
	    finalized.
	 */
	void (*destruct)(struct bufferevent *);

	/** Called when the timeouts on the bufferevent have changed.*/
	int (*adj_timeouts)(struct bufferevent *);

	/** Called to flush data. */
	int (*flush)(struct bufferevent *, short, enum bufferevent_flush_mode);

	/** Called to access miscellaneous fields. */
	int (*ctrl)(struct bufferevent *, enum bufferevent_ctrl_op, union bufferevent_ctrl_data *);
};

extern const struct bufferevent_ops bufferevent_ops_socket;
extern const struct bufferevent_ops bufferevent_ops_filter;
extern const struct bufferevent_ops bufferevent_ops_pair;

#define BEV_IS_SOCKET(bevp) ((bevp)->be_ops == &bufferevent_ops_socket)
#define BEV_IS_FILTER(bevp) ((bevp)->be_ops == &bufferevent_ops_filter)
#define BEV_IS_PAIR(bevp) ((bevp)->be_ops == &bufferevent_ops_pair)

#ifdef _WIN32
extern const struct bufferevent_ops bufferevent_ops_async;
#define BEV_IS_ASYNC(bevp) ((bevp)->be_ops == &bufferevent_ops_async)
#else
#define BEV_IS_ASYNC(bevp) 0
#endif

/** Initialize the shared parts of a bufferevent. */
int bufferevent_init_common_(struct bufferevent_private *, struct event_base *, const struct bufferevent_ops *, enum bufferevent_options options);

/** For internal use: temporarily stop all reads on bufev, until the conditions
 * in 'what' are over. */
void bufferevent_suspend_read_(struct bufferevent *bufev, bufferevent_suspend_flags what);
/** For internal use: clear the conditions 'what' on bufev, and re-enable
 * reading if there are no conditions left. */
void bufferevent_unsuspend_read_(struct bufferevent *bufev, bufferevent_suspend_flags what);

/** For internal use: temporarily stop all writes on bufev, until the conditions
 * in 'what' are over. */
void bufferevent_suspend_write_(struct bufferevent *bufev, bufferevent_suspend_flags what);
/** For internal use: clear the conditions 'what' on bufev, and re-enable
 * writing if there are no conditions left. */
void bufferevent_unsuspend_write_(struct bufferevent *bufev, bufferevent_suspend_flags what);

/*
  Disable a bufferevent.  Equivalent to bufferevent_disable(), but
  first resets 'connecting' flag to force EV_WRITE down for sure.

  XXXX this method will go away in the future; try not to add new users.
    See comment in evhttp_connection_reset_() for discussion.

  @param bufev the bufferevent to be disabled
  @param event any combination of EV_READ | EV_WRITE.
  @return 0 if successful, or -1 if an error occurred
  @see bufferevent_disable()
 */
int bufferevent_disable_hard_(struct bufferevent *bufev, short event);

/** Internal: Increment the reference count on bufev. */
void bufferevent_incref_(struct bufferevent *bufev);
/** Internal: Lock bufev and increase its reference count.
 * unlocking it otherwise. */
void bufferevent_incref(struct bufferevent *bufev);
/** Internal: Decrement the reference count on bufev.  Returns 1 if it freed
 * the bufferevent.*/
int bufferevent_decref(struct bufferevent *bufev);
/** Internal: Drop the reference count on bufev, freeing as necessary, and
 * unlocking it otherwise.  Returns 1 if it freed the bufferevent. */
int bufferevent_decref(struct bufferevent *bufev);

/** Internal: If callbacks are deferred and we have a read callback, schedule
 * a readcb.  Otherwise just run the readcb. Ignores watermarks. */
void bufferevent_run_readcb_(struct bufferevent *bufev, int options);
/** Internal: If callbacks are deferred and we have a write callback, schedule
 * a writecb.  Otherwise just run the writecb. Ignores watermarks. */
void bufferevent_run_writecb_(struct bufferevent *bufev, int options);
/** Internal: If callbacks are deferred and we have an eventcb, schedule
 * it to run with events "what".  Otherwise just run the eventcb.
 * See bufferevent_trigger_event for meaning of "options". */
void bufferevent_run_eventcb_(struct bufferevent *bufev, short what, int options);

/** Internal: Add the event 'ev' with timeout tv, unless tv is set to 0, in
 * which case add ev with no timeout. */
int bufferevent_add_event_(struct event *ev, const struct timeval *tv);

/* =========
 * These next functions implement timeouts for bufferevents that aren't doing
 * anything else with ev_read and ev_write, to handle timeouts.
 * ========= */
/** Internal use: Set up the ev_read and ev_write callbacks so that
 * the other "generic_timeout" functions will work on it.  Call this from
 * the constructor function. */
void bufferevent_init_generic_timeout_cbs_(struct bufferevent *bev);
/** Internal use: Add or delete the generic timeout events as appropriate.
 * (If an event is enabled and a timeout is set, we add the event.  Otherwise
 * we delete it.)  Call this from anything that changes the timeout values,
 * that enabled EV_READ or EV_WRITE, or that disables EV_READ or EV_WRITE. */
int bufferevent_generic_adj_timeouts_(struct bufferevent *bev);

enum bufferevent_options bufferevent_get_options_(struct bufferevent *bev);

/** Internal use: We have just successfully read data into an inbuf, so
 * reset the read timeout (if any). */
#define BEV_RESET_GENERIC_READ_TIMEOUT(bev)				\
	do {								\
		if (evutil_timerisset(&(bev)->timeout_read))		\
			event_add(&(bev)->ev_read, &(bev)->timeout_read, 0); \
	} while (0)
/** Internal use: We have just successfully written data from an inbuf, so
 * reset the read timeout (if any). */
#define BEV_RESET_GENERIC_WRITE_TIMEOUT(bev)				\
	do {								\
		if (evutil_timerisset(&(bev)->timeout_write))		\
			event_add(&(bev)->ev_write, &(bev)->timeout_write, 0); \
	} while (0)
#define BEV_DEL_GENERIC_READ_TIMEOUT(bev) event_del_general(&(bev)->ev_read)
#define BEV_DEL_GENERIC_WRITE_TIMEOUT(bev) event_del_general(&(bev)->ev_write)

/** Internal: Given a bufferevent, return its corresponding
 * bufferevent_private. */
#define BEV_UPCAST(b) EVUTIL_UPCAST((b), struct bufferevent_private, bev)

#ifdef __cplusplus
}
#endif


#endif /* BUFFEREVENT_INTERNAL_H_INCLUDED_ */
