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
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <netdb.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "addr.h"

#define _SS(x)	((struct sockaddr_storage *)(x))
#define _SA(x)	((struct sockaddr *)(x))

int
addr_unicast_masklen(int af)
{
	switch (af) {
	case AF_INET:
		return (32);
	case AF_INET6:
		return(128);
	default:
		return (-1);
	}
}

static inline int
masklen_valid(int af, u_int masklen)
{
	if (masklen < 0)
		return (-1);

	switch (af) {
	case AF_INET:
		return (masklen <= 32 ? 0 : -1);
	case AF_INET6:
		return (masklen <= 128 ? 0 : -1);
	default:
		return (-1);
	}
}


int
addr_xaddr_to_ss(struct xaddr *xa, struct sockaddr_storage *ss, u_int16_t port)
{
	struct sockaddr_in *in4 = (struct sockaddr_in *)ss;
	struct sockaddr_in6 *in6 = (struct sockaddr_in6 *)ss;

	if (xa == NULL || ss == NULL)
		return (-1);

	memset(ss, '\0', sizeof(*ss));
	switch (xa->af) {
	case AF_INET:
		in4->sin_len = sizeof(*in4);
		in4->sin_family = AF_INET;
		in4->sin_port = htons(port);
		memcpy(&in4->sin_addr, &xa->v4, sizeof(in4->sin_addr));
		break;
	case AF_INET6:
		in6->sin6_len = sizeof(*in6);
		in6->sin6_family = AF_INET6;
		in6->sin6_port = htons(port);
		memcpy(&in6->sin6_addr, &xa->v6, sizeof(in6->sin6_addr));
		in6->sin6_scope_id = xa->scope_id;
		break;
	default:
		return (-1);
	}
	return (0);
}

int
addr_ss_to_xaddr(struct sockaddr_storage *ss, struct xaddr *xa)
{
	struct sockaddr_in *in4 = (struct sockaddr_in *)ss;
	struct sockaddr_in6 *in6 = (struct sockaddr_in6 *)ss;

	memset(xa, '\0', sizeof(*xa));

	switch (ss->ss_family) {
	case AF_INET:
		xa->af = AF_INET;
		memcpy(&xa->v4, &in4->sin_addr, sizeof(xa->v4));
		break;
	case AF_INET6:
		xa->af = AF_INET6;
		memcpy(&xa->v6, &in6->sin6_addr, sizeof(xa->v6));
		xa->scope_id = in6->sin6_scope_id;
		break;
	default:
		return (-1);
	}

	return (0);
}

int
addr_invert(struct xaddr *n)
{
	int i;

	if (n == NULL)
		return (-1);

	switch (n->af) {
	case AF_INET:
		n->v4.s_addr = ~n->v4.s_addr;
		return (0);
	case AF_INET6:
		for (i = 0; i < 4; i++)
			n->addr32[i] = ~n->addr32[i];
		return (0);
	default:
		return (-1);
	}
}

int
addr_netmask(int af, u_int l, struct xaddr *n)
{
	int i;

	if (masklen_valid(af, l) != 0 || n == NULL)
		return (-1);

	memset(n, '\0', sizeof(*n));
	switch (af) {
	case AF_INET:
		n->af = AF_INET;
		n->v4.s_addr =
		    (l == 32) ? 0xffffffffUL : htonl(~(0xffffffffUL >> l));
		return (0);
	case AF_INET6:
		n->af = AF_INET6;
		for (i = 0; i < 4 && l >= 32; i++, l -= 32)
			n->addr32[i] = 0xffffffffU;
		if (i < 4 && l != 0)
			n->addr32[i] = htonl(~(0xffffffffU >> l));
		return (0);
	default:
		return (-1);
	}
}

int
addr_hostmask(int af, u_int l, struct xaddr *n)
{
	if (addr_netmask(af, l, n) == -1 || addr_invert(n) == -1)
		return (-1);
	return (0);
}

int
addr_and(struct xaddr *dst, const struct xaddr *a, const struct xaddr *b)
{
	int i;

	if (dst == NULL || a == NULL || b == NULL || a->af != b->af)
		return (-1);

	memcpy(dst, a, sizeof(*dst));
	switch (a->af) {
	case AF_INET:
		dst->v4.s_addr &= b->v4.s_addr;
		return (0);
	case AF_INET6:
		dst->scope_id = a->scope_id;
		for (i = 0; i < 4; i++)
			dst->addr32[i] &= b->addr32[i];
		return (0);
	default:
		return (-1);
	}
}

int
addr_or(struct xaddr *dst, const struct xaddr *a, const struct xaddr *b)
{
	int i;

	if (dst == NULL || a == NULL || b == NULL || a->af != b->af)
		return (-1);

	memcpy(dst, a, sizeof(*dst));
	switch (a->af) {
	case AF_INET:
		dst->v4.s_addr |= b->v4.s_addr;
		return (0);
	case AF_INET6:
		for (i = 0; i < 4; i++)
			dst->addr32[i] |= b->addr32[i];
		return (0);
	default:
		return (-1);
	}
}

int
addr_cmp(const struct xaddr *a, const struct xaddr *b)
{
	int i;

	if (a->af != b->af)
		return (a->af == AF_INET6 ? 1 : -1);

	switch (a->af) {
	case AF_INET:
		/*
		 * Can't just subtract here as 255.255.255.255 - 0.0.0.0 is
		 * too big to fit into a signed int
		 */
		if (a->v4.s_addr == b->v4.s_addr)
			return (0);
		return (ntohl(a->v4.s_addr) > ntohl(b->v4.s_addr) ? 1 : -1);
	case AF_INET6:;
		/*
		 * Do this a byte at a time to avoid the above issue and 
		 * any endian problems
		 */
		for (i = 0; i < 16; i++)
			if (a->addr8[i] - b->addr8[i] != 0)
				return (a->addr8[i] - b->addr8[i]);
		if (a->scope_id == b->scope_id)
			return (0);
		return (a->scope_id > b->scope_id ? 1 : -1);
	default:
		return (-1);
	}
}

int
addr_is_all0s(const struct xaddr *a)
{
	int i;

	switch (a->af) {
	case AF_INET:
		return (a->v4.s_addr == 0 ? 0 : -1);
	case AF_INET6:;
		for (i = 0; i < 4; i++)
			if (a->addr32[i] != 0)
				return (-1);
		return (0);
	default:
		return (-1);
	}
}

int
addr_host_is_all0s(const struct xaddr *a, u_int masklen)
{
	struct xaddr tmp_addr, tmp_mask, tmp_result;

	memcpy(&tmp_addr, a, sizeof(tmp_addr));
	if (addr_hostmask(a->af, masklen, &tmp_mask) == -1)
		return (-1);
	if (addr_and(&tmp_result, &tmp_addr, &tmp_mask) == -1)
		return (-1);
	return (addr_is_all0s(&tmp_result));
}

int
addr_host_is_all1s(const struct xaddr *a, u_int masklen)
{
	struct xaddr tmp_addr, tmp_mask, tmp_result;

	memcpy(&tmp_addr, a, sizeof(tmp_addr));
	if (addr_netmask(a->af, masklen, &tmp_mask) == -1)
		return (-1);
	if (addr_or(&tmp_result, &tmp_addr, &tmp_mask) == -1)
		return (-1);
	if (addr_invert(&tmp_result) == -1)
		return (-1);
	return (addr_is_all0s(&tmp_result));
}

int
addr_host_to_all0s(struct xaddr *a, u_int masklen)
{
	struct xaddr tmp_mask;
	
	if (addr_netmask(a->af, masklen, &tmp_mask) == -1)
		return (-1);
	if (addr_and(a, a, &tmp_mask) == -1)
		return (-1);
	return (0);
}

int
addr_host_to_all1s(struct xaddr *a, u_int masklen)
{
	struct xaddr tmp_mask;
	
	if (addr_hostmask(a->af, masklen, &tmp_mask) == -1)
		return (-1);
	if (addr_or(a, a, &tmp_mask) == -1)
		return (-1);
	return (0);
}

int
addr_pton(const char *p, struct xaddr *n)
{
	struct addrinfo hints, *ai;

	memset(&hints, '\0', sizeof(hints));
	hints.ai_flags = AI_NUMERICHOST;

	if (p == NULL || getaddrinfo(p, NULL, &hints, &ai) != 0)
		return (-1);
	
	if (ai == NULL || ai->ai_addr == NULL)
		return (-1);

	if (n != NULL && addr_ss_to_xaddr(_SS(ai->ai_addr), n) == -1) {
		freeaddrinfo(ai);
		return (-1);
	}

	freeaddrinfo(ai);
	return (0);
}

int
addr_ss_pton(const char *h, const char *s, struct sockaddr_storage *n)
{
	struct addrinfo hints, *ai;

	memset(&hints, '\0', sizeof(hints));
	hints.ai_flags = AI_NUMERICHOST;

	if (h == NULL || getaddrinfo(h, s, &hints, &ai) != 0)
		return (-1);

	if (ai == NULL || ai->ai_addr == NULL)
		return (-1);

	if (n != NULL)
		memcpy(n, &ai->ai_addr, SA_LEN(_SA(ai->ai_addr)));

	freeaddrinfo(ai);
	return (0);
}

int
addr_ntop(struct xaddr *n, char *p, size_t len)
{
	struct sockaddr_storage ss;
	if (addr_xaddr_to_ss(n, &ss, 0) == -1)
		return (-1);
	if (n == NULL || p == NULL || len == 0)
		return (-1);
	if (getnameinfo(_SA(&ss), SA_LEN(_SA(&ss)), p, len, NULL, 0, 
	    NI_NUMERICHOST) == -1)
		return (-1);

	return (0);
}

int
addr_ss_ntop(struct sockaddr_storage *ss, char *h, size_t hlen, 
    char *s, size_t slen)
{
	if (ss == NULL)
		return (-1);
	if (getnameinfo(_SA(ss), SA_LEN(_SA(ss)), h, hlen, s, slen, 
	    NI_NUMERICHOST) == -1)
		return (-1);

	return (0);
}

int
addr_pton_cidr(const char *p, struct xaddr *n, u_int *l)
{
	struct xaddr tmp;
	long unsigned int masklen = -1;
	char addrbuf[64], *mp, *cp;

	/* Don't modify argument */
	if (p == NULL || strlcpy(addrbuf, p, sizeof(addrbuf)) > sizeof(addrbuf))
		return (-1);

	if ((mp = strchr(addrbuf, '/')) != NULL) {
		*mp = '\0';
		mp++;
		masklen = strtoul(mp, &cp, 10);
		if (*mp == '\0' || *cp != '\0' || masklen > 128)
			return (-1);
	}

	if (addr_pton(addrbuf, &tmp) == -1)
		return (-1);

	if (mp == NULL)
		masklen = addr_unicast_masklen(tmp.af);
	if (masklen_valid(tmp.af, masklen) == -1)
		return (-1);

	if (n != NULL)
		memcpy(n, &tmp, sizeof(*n));
	if (l != NULL)
		*l = masklen;

	return (0);
}

int
addr_netmatch(const struct xaddr *host, const struct xaddr *net, u_int masklen)
{
	struct xaddr tmp_mask, tmp_result;

	if (host->af != net->af)
		return(-1);

	if (addr_netmask(host->af, masklen, &tmp_mask) == -1)
		return (-1);
	if (addr_and(&tmp_result, host, &tmp_mask) == -1)
		return (-1);
	return (addr_cmp(&tmp_result, net));
}

const char *
addr_ntop_buf(struct xaddr *a)
{
	static char hbuf[64];

	if (addr_ntop(a, hbuf, sizeof(hbuf)) == -1)
		return NULL;

	return (hbuf);
}

