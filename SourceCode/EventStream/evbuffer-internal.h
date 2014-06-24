/*
 * Copyright (c) 2000-2007 Niels Provos <provos@citi.umich.edu>
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
#ifndef EVBUFFER_INTERNAL_H_INCLUDED_
#define EVBUFFER_INTERNAL_H_INCLUDED_

#ifdef __cplusplus
extern "C" {
#endif

#include "config.h"
#include "util.h"
#include "event_struct.h"
#include "util-internal.h"
#include "defer-internal.h"

/* Experimental cb flag: "never deferred."  Implementation note:
 * these callbacks may get an inaccurate view of n_del/n_added in their
 * arguments. */
#define EVBUFFER_CB_NODEFER 2

#ifdef _WIN32
#include <winsock2.h>
#endif
#include <queue.h>

/* Minimum allocation for a chain.  We define this so that we're burning no
 * more than 5% of each allocation on overhead.  It would be nice to lose even
 * less space, though. */
#if EVENT__SIZEOF_VOID_P < 8
#define MIN_BUFFER_SIZE	512
#else
#define MIN_BUFFER_SIZE	1024
#endif

/** A single evbuffer callback for an evbuffer. This function will be invoked
 * when bytes are added to or removed from the evbuffer. */
struct evbuffer_cb_entry
{
	/** Structures to implement a doubly-linked queue of callbacks */
	LIST_ENTRY(evbuffer_cb_entry) next;
	/** The callback function to invoke when this callback is called. */
	evbuffer_cb_func cb_func;
	/** Argument to pass to cb. */
	void *cbarg;
	/** Currently set flags on this callback. */
	ev_uint32_t flags;
};

struct bufferevent;
struct evbuffer_chain;
struct evbuffer
{
	/** The first chain in this buffer's linked list of chains. */
	struct evbuffer_chain *first;
	/** The last chain in this buffer's linked list of chains. */
	struct evbuffer_chain *last;

	/** Pointer to the next pointer pointing at the 'last_with_data' chain.
	 *
	 * To unpack:
	 *
	 * The last_with_data chain is the last chain that has any data in it.
	 * If all chains in the buffer are empty, it is the first chain.
	 * If the buffer has no chains, it is NULL.
	 *
	 * The last_with_datap pointer points at _whatever 'next' pointer_
	 * points at the last_with_datap chain.  If the last_with_data chain
	 * is the first chain, or it is NULL, then the last_with_datap pointer
	 * is &buf->first.
	 */
	struct evbuffer_chain **last_with_datap;

	/** Total amount of bytes stored in all chains.*/
	size_t total_len;

	/** Number of bytes we have added to the buffer since we last tried to
	 * invoke callbacks. */
	size_t n_add_for_cb;
	/** Number of bytes we have removed from the buffer since we last
	 * tried to invoke callbacks. */
	size_t n_del_for_cb;

	/** True iff we should not allow changes to the front of the buffer
	 * (drains or prepends). */
	unsigned freeze_start : 1;
	/** True iff we should not allow changes to the end of the buffer
	 * (appends) */
	unsigned freeze_end : 1;
	/** True iff this evbuffer's callbacks are not invoked immediately
	 * upon a change in the buffer, but instead are deferred to be invoked
	 * from the event_base's loop.	Useful for preventing enormous stack
	 * overflows when we have mutually recursive callbacks, and for
	 * serializing callbacks in a single thread. */
	unsigned deferred_cbs : 1;
#ifdef _WIN32
	/** True iff this buffer is set up for overlapped IO. */
	unsigned is_overlapped : 1;
#endif

	/** Used to implement deferred callbacks. */
	struct event_base *cb_queue;

	/** A reference count on this evbuffer.	 When the reference count
	 * reaches 0, the buffer is destroyed.	Manipulated with
	 * evbuffer_incref and evbuffer_decref_and_unlock and
	 * evbuffer_free. */
	int refcnt;

	/** A struct event_callback handle to make all of this buffer's callbacks
	 * invoked from the event loop. */
	struct event_callback deferred;

	/** A doubly-linked-list of callback functions */
	LIST_HEAD(evbuffer_cb_queue, evbuffer_cb_entry) callbacks;

	/** The parent bufferevent object this evbuffer belongs to.
	 * NULL if the evbuffer stands alone. */
	struct bufferevent *parent;
};

/** A single item in an evbuffer. */
struct evbuffer_chain
{
	/** points to next buffer in the chain */
	struct evbuffer_chain *next;

	/** total allocation available in the buffer field. */
	size_t buffer_len;

	/** unused space at the beginning of buffer or an offset into a
	 * file for sendfile buffers. */
	ev_off_t misalign;

	/** Offset into buffer + misalign at which to start writing.
	 * In other words, the total number of bytes actually stored
	 * in buffer. */
	size_t off;

	/** Set if special handling is required for this chain */
	unsigned flags;
#define EVBUFFER_REFERENCE	0x0001	/**< a chain with a mem reference */
#define EVBUFFER_IMMUTABLE	0x0002	/**< read-only chain */
	/** a chain that mustn't be reallocated or freed, or have its contents
	 * memmoved, until the chain is un-pinned. */
#define EVBUFFER_MEM_PINNED_R	0x0004
#define EVBUFFER_MEM_PINNED_W	0x0008
#define EVBUFFER_MEM_PINNED_ANY (EVBUFFER_MEM_PINNED_R|EVBUFFER_MEM_PINNED_W)
	/** a chain that should be freed, but can't be freed until it is un-pinned. */
#define EVBUFFER_DANGLING	0x0010

	/** number of references to this chain */
	int refcnt;

	/** Usually points to the read-write memory belonging to this
	 * buffer allocated as part of the evbuffer_chain allocation.
	 * For mmap, this can be a read-only buffer and
	 * EVBUFFER_IMMUTABLE will be set in flags.  For sendfile, it
	 * may point to NULL.
	 */
	unsigned char *buffer;
};

/** callback for a reference chain; lets us know what to do with it when
 * we're done with it. Lives at the end of an evbuffer_chain with the
 * EVBUFFER_REFERENCE flag set */
struct evbuffer_chain_reference
{
	evbuffer_ref_cleanup_cb cleanupfn;
	void *extra;
};

#define EVBUFFER_CHAIN_SIZE sizeof(struct evbuffer_chain)
/** Return a pointer to extra data allocated along with an evbuffer. */
#define EVBUFFER_CHAIN_EXTRA(t, c) (t *)((struct evbuffer_chain *)(c) + 1)

/** Increase the reference count of buf by one. */
void evbuffer_incref(struct evbuffer *buf);
/** Pin a single buffer chain using a given flag. A pinned chunk may not be
 * moved or freed until it is unpinned. */
void evbuffer_chain_pin_(struct evbuffer_chain *chain, unsigned flag);
/** Unpin a single buffer chain using a given flag. */
void evbuffer_chain_unpin_(struct evbuffer_chain *chain, unsigned flag);
/** As evbuffer_free, but requires that we hold a lock on the buffer, and
 * releases the lock before freeing it and the buffer. */
void evbuffer_decref(struct evbuffer *buffer);

/** As evbuffer_expand, but does not guarantee that the newly allocated memory
 * is contiguous.  Instead, it may be split across two or more chunks. */
int evbuffer_expand_fast_(struct evbuffer *, size_t, int);

/** Helper: prepares for a readv/WSARecv call by expanding the buffer to
 * hold enough memory to read 'howmuch' bytes in possibly noncontiguous memory.
 * Sets up the one or two iovecs in 'vecs' to point to the free memory and its
 * extent, and *chainp to point to the first chain that we'll try to read into.
 * Returns the number of vecs used.
 */
int evbuffer_read_setup_vecs_(struct evbuffer *buf, ev_ssize_t howmuch,
    struct evbuffer_iovec *vecs, int n_vecs, struct evbuffer_chain ***chainp,
    int exact);

/* Helper macro: copies an evbuffer_iovec in ei to a win32 WSABUF in i. */
#define WSABUF_FROM_EVBUFFER_IOV(i,ei) do {		\
		(i)->buf = (ei)->iov_base;		\
		(i)->len = (unsigned long)(ei)->iov_len;	\
	} while (0)
/* XXXX the cast above is safe for now, but not if we allow mmaps on win64.
 * See note in buffer_iocp's launch_write function */

/** Set the parent bufferevent object for buf to bev */
void evbuffer_set_parent_(struct evbuffer *buf, struct bufferevent *bev);

void evbuffer_invoke_callbacks_(struct evbuffer *buf);

int evbuffer_get_callbacks_(
    struct evbuffer *buffer, struct event_callback **cbs, int max_cbs);

#ifdef __cplusplus
}
#endif

#endif /* EVBUFFER_INTERNAL_H_INCLUDED_ */
