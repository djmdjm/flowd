/*	$Id$	*/

/*
 * Copyright (c) 2004 Damien Miller <djm@mindrot.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef _PEER_H
#define _PEER_H

#include <sys/types.h>
#include "common.h"
#include "sys-queue.h"
#include "sys-tree.h"
#include "addr.h"

/*
 * Structure to hold per-peer state. NetFlow v.9 / IPFIX will require that we 
 * hold state for each peer to retain templates. This peer state is stored in
 * a splay tree for quick access by sender address and in a deque so we can
 * do fast LRU deletions on overflow
 */
struct peer_state {
	SPLAY_ENTRY(peer_state) tp;
	TAILQ_ENTRY(peer_state) lp;
	struct xaddr from;
	u_int64_t npackets, nflows, ninvalid;
	struct timeval firstseen, lastvalid;
	u_int last_version;
};

/* Structures for top of peer state tree and head of list */
SPLAY_HEAD(peer_tree, peer_state);
TAILQ_HEAD(peer_list, peer_state);

/* Peer stateholding structure */
struct peers {
	struct peer_tree peer_tree;
	struct peer_list peer_list;
	u_int max_peers, num_peers, num_forced;
};


struct peer_state *new_peer(struct peers *peers, struct flowd_config *conf,
    struct xaddr *addr);
void scrub_peers(struct flowd_config *conf, struct peers *peers);
void update_peer(struct peers *peers, struct peer_state *peer, u_int nflows, 
    u_int netflow_version);
struct peer_state *find_peer(struct peers *peers, struct xaddr *addr);
void dump_peers(struct peers *peers);

#endif /* _PEER_H */
