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

#include <sys/types.h>
#include <sys/time.h>

#include <unistd.h>
#include <stdlib.h>
#include <syslog.h>
#include <string.h>
#include <stdio.h>
#include <time.h>

#include "sys-queue.h"
#include "sys-tree.h"
#include "flowd.h"
#include "peer.h"

RCSID("$Id$");

/* Peer state housekeeping functions */
static int
peer_compare(struct peer_state *a, struct peer_state *b)
{
	return (addr_cmp(&a->from, &b->from));
}

/* Generate functions for peer state tree */
SPLAY_PROTOTYPE(peer_tree, peer_state, tp, peer_compare);
SPLAY_GENERATE(peer_tree, peer_state, tp, peer_compare);

static void
delete_peer(struct peers *peers, struct peer_state *peer)
{
	TAILQ_REMOVE(&peers->peer_list, peer, lp);
	SPLAY_REMOVE(peer_tree, &peers->peer_tree, peer);
	free(peer);
	peers->num_peers--;
}

struct peer_state *
new_peer(struct peers *peers, struct flowd_config *conf, struct xaddr *addr)
{
	struct peer_state *peer;
	struct allowed_device *ad;

	/* Check for address authorization */
	if (TAILQ_FIRST(&conf->allowed_devices) != NULL) {
		TAILQ_FOREACH(ad, &conf->allowed_devices, entry) {
			if (addr_netmatch(addr, &ad->addr, ad->masklen) == 0)
		 		break;
		}
		if (ad == NULL)
			return (NULL);
	}

	/* If we have overflowed our peer table, then kick out the LRU peer */
	peers->num_peers++;
	if (peers->num_peers > peers->max_peers) {
		peers->num_forced++;
		peer = TAILQ_LAST(&peers->peer_list, peer_list);
		logit(LOG_WARNING, "forced deletion of peer %s", 
		    addr_ntop_buf(&peer->from));
		/* XXX ratelimit errors */
		delete_peer(peers, peer);
	}

	if ((peer = calloc(1, sizeof(*peer))) == NULL)
		logerrx("%s: calloc failed", __func__);
	memcpy(&peer->from, addr, sizeof(peer->from));

	logit(LOG_DEBUG, "new peer %s", addr_ntop_buf(addr));

	TAILQ_INSERT_HEAD(&peers->peer_list, peer, lp);
	SPLAY_INSERT(peer_tree, &peers->peer_tree, peer);
	gettimeofday(&peer->firstseen, NULL);
	
	return (peer);
}

void
scrub_peers(struct flowd_config *conf, struct peers *peers)
{
	struct peer_state *peer, *npeer;
	struct allowed_device *ad;

	/* Check for address authorization */
	if (TAILQ_FIRST(&conf->allowed_devices) == NULL)
		return;

	for (peer = TAILQ_FIRST(&peers->peer_list); peer != NULL;) {
		npeer = TAILQ_NEXT(peer, lp);

		TAILQ_FOREACH(ad, &conf->allowed_devices, entry) {
			if (addr_netmatch(&peer->from, &ad->addr,
			    ad->masklen) == 0)
		 		break;
		}
		if (ad == NULL) {
			logit(LOG_WARNING, "delete peer %s (no longer allowed)",
			    addr_ntop_buf(&peer->from));
			delete_peer(peers, peer);
		}
		peer = npeer;
	}
}

void
update_peer(struct peers *peers, struct peer_state *peer, u_int nflows, 
    u_int netflow_version)
{
	/* Push peer to front of LRU queue, if it isn't there already */
	if (peer != TAILQ_FIRST(&peers->peer_list)) {
		TAILQ_REMOVE(&peers->peer_list, peer, lp);
		TAILQ_INSERT_HEAD(&peers->peer_list, peer, lp);
	}
	gettimeofday(&peer->lastvalid, NULL);
	peer->nflows += nflows;
	peer->npackets++;
	peer->last_version = netflow_version;
	logit(LOG_DEBUG, "update peer %s", addr_ntop_buf(&peer->from));
}

struct peer_state *
find_peer(struct peers *peers, struct xaddr *addr)
{
	struct peer_state tmp, *peer;

	bzero(&tmp, sizeof(tmp));
	memcpy(&tmp.from, addr, sizeof(tmp.from));

	peer = SPLAY_FIND(peer_tree, &peers->peer_tree, &tmp);
	logit(LOG_DEBUG, "%s: found %s", __func__,
	    peer == NULL ? "NONE" : addr_ntop_buf(addr));

	return (peer);
}

void
dump_peers(struct peers *peers)
{
	struct peer_state *peer;
	u_int i;

	logit(LOG_INFO, "Peer state: %u of %u in used, %u forced deletions",
	    peers->num_peers, peers->max_peers, peers->num_forced);
	i = 0;
	SPLAY_FOREACH(peer, peer_tree, &peers->peer_tree) {
		logit(LOG_INFO,
		    "peer %u - %s: %llu packets %llu flows %llu invalid",
		    i, addr_ntop_buf(&peer->from), 
		    peer->npackets, peer->nflows,
		    peer->ninvalid);
		logit(LOG_INFO, "peer %u - %s: first seen %s.%03u",
		    i, addr_ntop_buf(&peer->from), 
		    iso_time(peer->firstseen.tv_sec, 0), 
		    (u_int)(peer->firstseen.tv_usec / 1000));
		logit(LOG_INFO, "peer %u - %s: last valid %s.%03u netflow v.%u",
		    i, addr_ntop_buf(&peer->from), 
		    iso_time(peer->lastvalid.tv_sec, 0), 
		    (u_int)(peer->lastvalid.tv_usec / 1000), 
		    peer->last_version);
		i++;
	}
}
