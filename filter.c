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

#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "sys-queue.h"
#include "flowd.h"
#include "filter.h"
#include "store.h"

RCSID("$Id$");

/* #define FILTER_DEBUG */

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

#define FRNEG(what) \
	(rule->match.match_negate & FF_MATCH_##what) ? "! " : ""

	if (rule->match.match_what & FF_MATCH_AGENT_ADDR) {
		snprintf(tmpbuf, sizeof(tmpbuf), "agent %s%s/%d ",
		    FRNEG(AGENT_ADDR), addr_ntop_buf(&rule->match.agent_addr), 
		    rule->match.agent_masklen);
		strlcat(rulebuf, tmpbuf, sizeof(rulebuf));
	}
	if (rule->match.match_what & FF_MATCH_SRC_ADDR) {
		snprintf(tmpbuf, sizeof(tmpbuf), "src %s%s/%d ",
		    FRNEG(SRC_ADDR), addr_ntop_buf(&rule->match.src_addr), 
		    rule->match.src_masklen);
		strlcat(rulebuf, tmpbuf, sizeof(rulebuf));
	}
	if (rule->match.match_what & FF_MATCH_SRC_PORT) {
		if (!(rule->match.match_what & FF_MATCH_SRC_ADDR))
			strlcat(rulebuf, "src any ", sizeof(rulebuf));
		snprintf(tmpbuf, sizeof(tmpbuf), "port %s%d ",
		    FRNEG(SRC_PORT), rule->match.src_port);
		strlcat(rulebuf, tmpbuf, sizeof(rulebuf));
	}
	if (rule->match.match_what & FF_MATCH_DST_ADDR) {
		snprintf(tmpbuf, sizeof(tmpbuf), "dst %s%s/%d ",
		    FRNEG(DST_ADDR), addr_ntop_buf(&rule->match.dst_addr), 
		    rule->match.dst_masklen);
		strlcat(rulebuf, tmpbuf, sizeof(rulebuf));
	}
	if (rule->match.match_what & FF_MATCH_DST_PORT) {
		if (!(rule->match.match_what & FF_MATCH_DST_ADDR))
			strlcat(rulebuf, "dst any ", sizeof(rulebuf));
		snprintf(tmpbuf, sizeof(tmpbuf), "port %s%d ",
		    FRNEG(DST_PORT), rule->match.dst_port);
		strlcat(rulebuf, tmpbuf, sizeof(rulebuf));
	}
	if (rule->match.match_what & FF_MATCH_PROTOCOL) {
		snprintf(tmpbuf, sizeof(tmpbuf), "proto %s%d ",
		    FRNEG(PROTOCOL), rule->match.proto);
		strlcat(rulebuf, tmpbuf, sizeof(rulebuf));
	}
	if (rule->match.match_what & FF_MATCH_TOS) {
		snprintf(tmpbuf, sizeof(tmpbuf), "tos %s0x%x ",
		FRNEG(TOS), rule->match.tos);
		strlcat(rulebuf, tmpbuf, sizeof(rulebuf));
	}
#undef FRNEG

	snprintf(tmpbuf, sizeof(tmpbuf),
	    "# evaluations %llu matches %llu wins %llu",
	    rule->evaluations, rule->matches, rule->wins);
	strlcat(rulebuf, tmpbuf, sizeof(rulebuf));

	return (rulebuf);
}

static int
flow_match(struct filter_rule *rule, struct store_flow_complete *flow)
{
	int m;

#define FRNEG(what) (rule->match.match_negate & FF_MATCH_##what)
#define FRMATCH(what) (rule->match.match_what & FF_MATCH_##what)

	if (FRMATCH(AGENT_ADDR)) {
		m = (addr_netmatch(&flow->agent_addr, &rule->match.agent_addr,
		    rule->match.agent_masklen) == 0);
		if ((FRNEG(AGENT_ADDR) && m) || (!FRNEG(AGENT_ADDR) && !m))
			return (0);
	}

	if (FRMATCH(SRC_ADDR)) {
		m = (addr_netmatch(&flow->src_addr, &rule->match.src_addr,
		    rule->match.src_masklen) == 0);
		if ((FRNEG(SRC_ADDR) && m) || (!FRNEG(SRC_ADDR) && !m))
			return (0);
	}

	if (FRMATCH(DST_ADDR)) {
		m = (addr_netmatch(&flow->dst_addr, &rule->match.dst_addr,
		    rule->match.dst_masklen) == 0);
		if ((FRNEG(DST_ADDR) && m) || (!FRNEG(DST_ADDR) && !m))
			return (0);
	}

	if (FRMATCH(SRC_PORT)) {
		m = (ntohs(flow->ports.src_port) == rule->match.src_port);
		if ((FRNEG(SRC_PORT) && m) || (!FRNEG(SRC_PORT) && !m))
			return (0);
	}

	if (FRMATCH(DST_PORT)) {
		m = (ntohs(flow->ports.dst_port) == rule->match.dst_port);
		if ((FRNEG(DST_PORT) && m) || (!FRNEG(DST_PORT) && !m))
			return (0);
	}

	if (FRMATCH(PROTOCOL)) {
		m = (flow->pft.protocol == rule->match.proto);
		if ((FRNEG(PROTOCOL) && m) || (!FRNEG(PROTOCOL) && !m))
			return (0);
	}

	if (FRMATCH(TOS)) {
		m = (flow->pft.tos == rule->match.tos);
		if ((FRNEG(TOS) && m) || (!FRNEG(TOS) && !m))
			return (0);
	}
#undef FRMATCH
#undef FRNEG

	return (1);
}

u_int
filter_flow(struct store_flow_complete *flow, struct filter_list *filter)
{
	u_int action = FF_ACTION_ACCEPT;
	struct filter_rule *fr, *last_rule;
	int i, m;

	i = 0;
	last_rule = NULL;
	TAILQ_FOREACH(fr, filter, entry) {
		m = flow_match(fr, flow);
		fr->evaluations++;

#ifdef FILTER_DEBUG
		logit(LOG_DEBUG, "%s: match %s = %d action %d/%d", __func__,
		    format_rule(fr), m, fr->action.action_what, fr->action.tag);
#endif

		if (m) {
			fr->matches++;
			last_rule = fr;
			if (fr->quick)
				break;
		}
	}

	if (last_rule != NULL) {
		last_rule->wins++;
		action = last_rule->action.action_what;
		if (action == FF_ACTION_TAG) {
			flow->hdr.fields = ntohl(flow->hdr.fields);
			flow->hdr.fields |= STORE_FIELD_TAG;
			flow->hdr.fields = htonl(flow->hdr.fields);
			flow->tag.tag = htonl(last_rule->action.tag);
			action = FF_ACTION_ACCEPT;
		}
	}

#ifdef FILTER_DEBUG
	logit(LOG_DEBUG, "%s: return %d", __func__, action);
#endif

	return (action);
}

