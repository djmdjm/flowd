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
#include <sys/queue.h>

#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "flowd.h"
#include "filter.h"
#include "store.h"

const char *
format_rule(struct filter_rule *rule)
{
	char tmpbuf[128];
	static char rulebuf[1024];

	*rulebuf = '\0';

	if (rule->action.action_what == FF_ACTION_ACCEPT)
		strlcat(rulebuf, "accept ", sizeof(rulebuf));
	else if (rule->action.action_what == FF_ACTION_DISCARD)
		strlcat(rulebuf, "discard ", sizeof(rulebuf));
	else if (rule->action.action_what == FF_ACTION_TAG) {
		snprintf(tmpbuf, sizeof(tmpbuf), "tag %lu ",
		    (u_long)rule->action.tag);
		strlcat(rulebuf, tmpbuf, sizeof(rulebuf));
	} else
		strlcat(rulebuf, "ERROR ", sizeof(rulebuf));

	if (rule->quick)
		strlcat(rulebuf, "quick ", sizeof(rulebuf));

	if (rule->match.match_what & FF_MATCH_AGENT_ADDR) {
		snprintf(tmpbuf, sizeof(tmpbuf), "agent %s/%d ",
		    addr_ntop_buf(&rule->match.agent_addr), 
		    rule->match.agent_masklen);
		strlcat(rulebuf, tmpbuf, sizeof(rulebuf));
	}

	if (rule->match.match_what & 
	    (FF_MATCH_SRC_ADDR|FF_MATCH_SRC_PORT)) {
		snprintf(tmpbuf, sizeof(tmpbuf), "src %s/%d ",
		    addr_ntop_buf(&rule->match.src_addr), 
		    rule->match.src_masklen);
		strlcat(rulebuf, tmpbuf, sizeof(rulebuf));
	}
	if (rule->match.match_what & FF_MATCH_SRC_PORT) {
		snprintf(tmpbuf, sizeof(tmpbuf), "port %d ",
		    rule->match.src_port);
		strlcat(rulebuf, tmpbuf, sizeof(rulebuf));
	}

	if (rule->match.match_what & 
	    (FF_MATCH_DST_ADDR|FF_MATCH_DST_PORT)) {
		snprintf(tmpbuf, sizeof(tmpbuf), "dst %s/%d ",
		    addr_ntop_buf(&rule->match.dst_addr), 
		    rule->match.dst_masklen);
		strlcat(rulebuf, tmpbuf, sizeof(rulebuf));
	}
	if (rule->match.match_what & FF_MATCH_DST_PORT) {
		snprintf(tmpbuf, sizeof(tmpbuf), "port %d ",
		    rule->match.dst_port);
		strlcat(rulebuf, tmpbuf, sizeof(rulebuf));
	}

	if (rule->match.match_what & FF_MATCH_PROTOCOL) {
		snprintf(tmpbuf, sizeof(tmpbuf), "proto %d ",
		    rule->match.proto);
		strlcat(rulebuf, tmpbuf, sizeof(rulebuf));
	}

	if (rule->match.match_what & FF_MATCH_TOS) {
		snprintf(tmpbuf, sizeof(tmpbuf), "tos 0x%x ", rule->match.tos);
		strlcat(rulebuf, tmpbuf, sizeof(rulebuf));
	}
	return (rulebuf);
}

static int
flow_match(struct filter_rule *rule, struct store_flow_complete *flow)
{
	if ((rule->match.match_what & FF_MATCH_AGENT_ADDR) && 
	    addr_netmatch(&flow->agent_addr, &rule->match.agent_addr,
	    rule->match.agent_masklen) != 0)
		return (0);

	if ((rule->match.match_what & FF_MATCH_SRC_ADDR) && 
	    addr_netmatch(&flow->src_addr, &rule->match.src_addr,
		    rule->match.src_masklen) != 0)
		return (0);

	if ((rule->match.match_what & FF_MATCH_DST_ADDR) && 
	    addr_netmatch(&flow->dst_addr, &rule->match.dst_addr,
		    rule->match.dst_masklen) != 0)
		return (0);

	if ((rule->match.match_what & FF_MATCH_SRC_PORT) && 
	    ntohs(flow->ports.src_port) != rule->match.src_port)
		return (0);

	if ((rule->match.match_what & FF_MATCH_DST_PORT) && 
	    ntohs(flow->ports.dst_port) != rule->match.dst_port)
		return (0);

	if ((rule->match.match_what & FF_MATCH_PROTOCOL) &&
	    flow->pft.protocol != rule->match.proto)
		return (0);

	if ((rule->match.match_what & FF_MATCH_TOS) &&
	    flow->pft.tos != rule->match.tos)
		return (0);

	return (1);
}

u_int
filter_flow(struct store_flow_complete *flow, struct filter_list *filter)
{
	u_int action = FF_ACTION_ACCEPT;
	u_int tag = 0;
	struct filter_rule *fr;
	int i;

	i = 0;
	TAILQ_FOREACH(fr, filter, entry) {
		/* XXX - check necessary fields are present */

		if (!flow_match(fr, flow))
			continue;

		action = fr->action.action_what;
		tag = fr->action.tag;

		if (fr->quick)
			break;
	}

	if (action == FF_ACTION_TAG) {
		flow->hdr.tag = htonl(tag);
		action = FF_ACTION_ACCEPT;
	}

	return (action);
}

