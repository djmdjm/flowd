/* $Id$ */

/*
 * Copyright (c) 2004 Damien Miller <djm@mindrot.org>
 * Copyright (c) 2002, 2003, 2004 Henning Brauer <henning@openbsd.org>
 * Copyright (c) 2001 Markus Friedl.  All rights reserved.
 * Copyright (c) 2001 Daniel Hartmeier.  All rights reserved.
 * Copyright (c) 2001 Theo de Raadt.  All rights reserved.
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

%{
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>

#include "flowd.h"
#include "addr.h"

static struct flowd_config	*conf = NULL;

static FILE			*fin = NULL;
static int			 lineno = 1;
static int			 errors = 0;
static int			 pdebug = 1;
char				*infile;

int	yyerror(const char *, ...);
int	yyparse(void);
int	kw_cmp(const void *, const void *);
int	lookup(char *);
int	lgetc(FILE *);
int	lungetc(int);
int	findeol(void);
int	yylex(void);
int	atoul(char *, u_long *);

TAILQ_HEAD(symhead, sym)	 symhead = TAILQ_HEAD_INITIALIZER(symhead);
struct sym {
	TAILQ_ENTRY(sym)	 entry;
	int			 used;
	int			 persist;
	char			*nam;
	char			*val;
};

int	 symset(const char *, const char *, int);
char	*symget(const char *);

typedef struct {
	union {
		u_int32_t			number;
		char				*string;
		u_int8_t			u8;
		struct {
			struct xaddr		addr;
			unsigned int		len;
		} prefix;
		struct {
			struct xaddr		addr;
			u_int16_t		port;
		} addrport;
		struct filter_action		filter_action;
		struct filter_match		filter_match;
	} v;
	int lineno;
} YYSTYPE;

%}

%token	LISTEN ON LOGFILE
%token	TAG DISCARD QUICK AGENT SRC DST PORT PROTO TOS ANY
%token	ERROR
%token	<v.string>		STRING
%type	<v.number>		number quick
%type	<v.string>		string
%type	<v.addrport>		address_port
%type	<v.prefix>		prefix prefix_or_any
%type	<v.filter_match>	match_agent match_src match_dst match_proto match_tos
%type	<v.filter_action>	action
%%

grammar		: /* empty */
		| grammar '\n'
		| grammar conf_main '\n'
		| grammar varset '\n'
		| grammar filterrule '\n'
		| grammar error '\n'		{ errors++; }
		;

number		: STRING			{
			u_long	ulval;

			if (atoul($1, &ulval) == -1) {
				yyerror("\"%s\" is not a number", $1);
				free($1);
				YYERROR;
			} else
				$$ = ulval;
			free($1);
		}
		;

string		: string STRING				{
			if (asprintf(&$$, "%s %s", $1, $2) == -1)
				errx(1, "string: asprintf");
			free($1);
			free($2);
		}
		| STRING
		;

varset		: STRING '=' string		{
			if (conf->opts & FLOWD_OPT_VERBOSE)
				fprintf(stderr, "%s = \"%s\"\n", $1, $3);
			if (symset($1, $3, 0) == -1)
				errx(1, "cannot store variable");
			free($1);
			free($3);
		}
		;

address_port	: STRING		{
			char *colon, *cp;
			unsigned long port;

			cp = $1;

			if ((colon = strrchr(cp, ':')) == NULL) {
				yyerror("missing port specification \"%s\"", $1);
				free($1);
				YYERROR;
			}

			*colon++ = '\0';

			/* Allow [blah]:foo for IPv6 */
			if (*cp == '[' && *(colon - 2) == ']') {
				cp++;
				*(colon - 2) = '\0';
			}

			if (atoul(colon, &port) == -1 || port == 0 || 
			    port > 65535) {
				yyerror("Invalid port number");
				free($1);
				YYERROR;
			}

			if (!addr_pton(cp, &$$.addr) == -1) {
				yyerror("could not parse address \"%s\"", cp);
				free($1);
				YYERROR;
			}
			$$.port = port;

			free($1);
		}
		;

prefix		: STRING '/' number	{
			char	*s;

			if (asprintf(&s, "%s/%u", $1, $3) == -1)
				errx(1, "string: asprintf");

			free($1);

			if (!addr_pton_cidr(s, &$$.addr, &$$.len) == -1) {
				yyerror("could not parse address \"%s\"", s);
				free(s);
				YYERROR;
			}
			free(s);
		}
		| STRING		{
			if (!addr_pton_cidr($1, &$$.addr, &$$.len) == -1) {
				yyerror("could not parse address \"%s\"", $1);
				free($1);
				YYERROR;
			}
			free($1);
		}
		;

prefix_or_any	: ANY			{ memset(&$$, 0, sizeof($$)); }
		| prefix		{ $$ = $1; }
		;

conf_main	: LISTEN ON address_port	{
			struct listen_addr	*la;

			if ((la = calloc(1, sizeof(*la))) == NULL)
				errx(1, "listen_on: calloc");

			la->fd = -1;
			la->addr = $3.addr;
			la->port = $3.port;
			TAILQ_INSERT_TAIL(&conf->listen_addrs, la, entry);
		}
		| LOGFILE string		{
			if (conf->log_file != NULL)
				free(conf->log_file);
			conf->log_file = $2;
		}
		;

filterrule	: action quick match_agent match_src match_dst match_proto match_tos
		{
			struct filter_rule	*r;

			if ((r = calloc(1, sizeof(*r))) == NULL)
				errx(1, "filterrule: calloc");

			r->action = $1;
			r->quick = $2;

			r->match.agent_addr = $3.agent_addr;
			r->match.agent_masklen = $3.agent_masklen;
			r->match.match_what |= $3.match_what;

			r->match.src_addr = $4.src_addr;
			r->match.src_masklen = $4.src_masklen;
			r->match.src_port = $4.src_port;
			r->match.match_what |= $4.match_what;

			r->match.dst_addr = $5.dst_addr;
			r->match.dst_masklen = $5.dst_masklen;
			r->match.dst_port = $5.dst_port;
			r->match.match_what |= $5.match_what;

			r->match.proto = $6.proto;
			r->match.match_what |= $6.match_what;

			r->match.tos = $7.tos;
			r->match.match_what |= $7.match_what;

			TAILQ_INSERT_TAIL(&conf->filter_list, r, entry);
		}
		;

action		: DISCARD	{
			bzero(&$$, sizeof($$));
			$$.action_what = FF_ACTION_DISCARD;
		}
		| TAG number	{
			bzero(&$$, sizeof($$));
			$$.action_what = FF_ACTION_TAG;
			$$.tag = $2;
		}
		;

quick		: /* empty */	{ $$ = 0; }
		| QUICK		{ $$ = 1; }
		;

match_agent	: /* empty */			{ bzero(&$$, sizeof($$)); }
		| AGENT prefix			{
			bzero(&$$, sizeof($$));
			memcpy(&$$.agent_addr, &$2.addr, sizeof($$.agent_addr));
			$$.agent_masklen = $2.len;
			$$.match_what |= FF_MATCH_AGENT_ADDR;
		}
		;

match_src	: /* empty */			{ bzero(&$$, sizeof($$)); }
		| SRC prefix_or_any			{
			bzero(&$$, sizeof($$));
			memcpy(&$$.src_addr, &$2.addr, sizeof($$.src_addr));
			$$.src_masklen = $2.len;
			$$.match_what |= FF_MATCH_SRC_ADDR;
		}
		| SRC prefix_or_any PORT number	{
			bzero(&$$, sizeof($$));
			memcpy(&$$.src_addr, &$2.addr, sizeof($$.src_addr));
			$$.src_masklen = $2.len;
			$$.src_port = $4;
			if ($$.src_port <= 0 || $$.src_port > 65535) {
				yyerror("invalid port number");
				YYERROR;
			}
			$$.match_what |= FF_MATCH_SRC_PORT;
			if ($$.src_masklen != 0)
				$$.match_what |= FF_MATCH_SRC_ADDR;
		}
		;

match_dst	: /* empty */			{ bzero(&$$, sizeof($$)); }
		| DST prefix_or_any			{
			bzero(&$$, sizeof($$));
			memcpy(&$$.dst_addr, &$2.addr, sizeof($$.dst_addr));
			$$.dst_masklen = $2.len;
			$$.match_what |= FF_MATCH_DST_ADDR;
		}
		| DST prefix_or_any PORT number	{
			bzero(&$$, sizeof($$));
			memcpy(&$$.dst_addr, &$2.addr, sizeof($$.dst_addr));
			$$.dst_masklen = $2.len;
			$$.dst_port = $4;
			if ($$.dst_port <= 0 || $$.dst_port > 65535) {
				yyerror("invalid port number");
				YYERROR;
			}
			$$.match_what |= FF_MATCH_DST_PORT;
			if ($$.src_masklen != 0)
				$$.match_what |= FF_MATCH_DST_ADDR;
		}
		;

match_proto	: /* empty */			{ bzero(&$$, sizeof($$)); }
		| PROTO string		{
			unsigned long proto;

			bzero(&$$, sizeof($$));
			if (strcasecmp($2, "tcp") == 0)
				proto = IPPROTO_TCP;
			else if (strcasecmp($2, "tcp") == 0)
				proto = IPPROTO_UDP;
			else if (atoul($2, &proto) == -1 || proto == 0 || 
			    proto > 255) {
				yyerror("Invalid protocol");
				free($2);
				YYERROR;
			}
			$$.proto = proto;
			$$.match_what |= FF_MATCH_PROTOCOL;
		}
		;

match_tos	: /* empty */			{ bzero(&$$, sizeof($$)); }
		| TOS number		{
			bzero(&$$, sizeof($$));
			if ($2 > 0xff) {
				yyerror("Invalid ToS");
				YYERROR;
			}
			$$.tos = $2;
			$$.match_what |= FF_MATCH_TOS;
		}
		;

%%

struct keywords {
	const char	*k_name;
	int		 k_val;
};

int
yyerror(const char *fmt, ...)
{
	va_list		 ap;
	char		*nfmt;

	errors = 1;
	va_start(ap, fmt);
	if (asprintf(&nfmt, "%s:%d: %s", infile, yylval.lineno, fmt) == -1)
		errx(1, "yyerror asprintf");
	vfprintf(stderr, nfmt, ap);
	va_end(ap);
	free(nfmt);
	fprintf(stderr, "\n");
	return (0);
}

int
kw_cmp(const void *k, const void *e)
{
	return (strcmp(k, ((const struct keywords *)e)->k_name));
}

int
lookup(char *s)
{
	/* this has to be sorted always */
	static const struct keywords keywords[] = {
		{ "any",		ANY},
		{ "agent",		AGENT},
		{ "discard",		DISCARD},
		{ "dst",		DST},
		{ "listen",		LISTEN},
		{ "logfile",		LOGFILE},
		{ "on",			ON},
		{ "port",		PORT},
		{ "proto",		PROTO},
		{ "quick",		QUICK},
		{ "src",		SRC},
		{ "tag",		TAG},
		{ "tos",		TOS},
	};
	const struct keywords	*p;

	p = bsearch(s, keywords, sizeof(keywords)/sizeof(keywords[0]),
	    sizeof(keywords[0]), kw_cmp);

	if (p) {
		if (pdebug > 1)
			fprintf(stderr, "%s: %d\n", s, p->k_val);
		return (p->k_val);
	} else {
		if (pdebug > 1)
			fprintf(stderr, "string: %s\n", s);
		return (STRING);
	}
}

#define MAXPUSHBACK	128

char	*parsebuf;
int	 parseindex;
char	 pushback_buffer[MAXPUSHBACK];
int	 pushback_index = 0;

int
lgetc(FILE *f)
{
	int	c, next;

	if (parsebuf) {
		/* Read character from the parsebuffer instead of input. */
		if (parseindex >= 0) {
			c = parsebuf[parseindex++];
			if (c != '\0')
				return (c);
			parsebuf = NULL;
		} else
			parseindex++;
	}

	if (pushback_index)
		return (pushback_buffer[--pushback_index]);

	while ((c = getc(f)) == '\\') {
		next = getc(f);
		if (next != '\n') {
			if (isspace(next))
				yyerror("whitespace after \\");
			ungetc(next, f);
			break;
		}
		yylval.lineno = lineno;
		lineno++;
	}
	if (c == '\t' || c == ' ') {
		/* Compress blanks to a single space. */
		do {
			c = getc(f);
		} while (c == '\t' || c == ' ');
		ungetc(c, f);
		c = ' ';
	}

	return (c);
}

int
lungetc(int c)
{
	if (c == EOF)
		return (EOF);
	if (parsebuf) {
		parseindex--;
		if (parseindex >= 0)
			return (c);
	}
	if (pushback_index < MAXPUSHBACK-1)
		return (pushback_buffer[pushback_index++] = c);
	else
		return (EOF);
}

int
findeol(void)
{
	int	c;

	parsebuf = NULL;
	pushback_index = 0;

	/* skip to either EOF or the first real EOL */
	while (1) {
		c = lgetc(fin);
		if (c == '\n') {
			lineno++;
			break;
		}
		if (c == EOF)
			break;
	}
	return (ERROR);
}

int
yylex(void)
{
	char	 buf[8096];
	char	*p, *val;
	int	 endc, c;
	int	 token;

top:
	p = buf;
	while ((c = lgetc(fin)) == ' ')
		; /* nothing */

	yylval.lineno = lineno;
	if (c == '#')
		while ((c = lgetc(fin)) != '\n' && c != EOF)
			; /* nothing */
	if (c == '$' && parsebuf == NULL) {
		while (1) {
			if ((c = lgetc(fin)) == EOF)
				return (0);

			if (p + 1 >= buf + sizeof(buf) - 1) {
				yyerror("string too long");
				return (findeol());
			}
			if (isalnum(c) || c == '_') {
				*p++ = (char)c;
				continue;
			}
			*p = '\0';
			lungetc(c);
			break;
		}
		val = symget(buf);
		if (val == NULL) {
			yyerror("macro \"%s\" not defined", buf);
			return (findeol());
		}
		parsebuf = val;
		parseindex = 0;
		goto top;
	}

	switch (c) {
	case '\'':
	case '"':
		endc = c;
		while (1) {
			if ((c = lgetc(fin)) == EOF)
				return (0);
			if (c == endc) {
				*p = '\0';
				break;
			}
			if (c == '\n') {
				lineno++;
				continue;
			}
			if (p + 1 >= buf + sizeof(buf) - 1) {
				yyerror("string too long");
				return (findeol());
			}
			*p++ = (char)c;
		}
		yylval.v.string = strdup(buf);
		if (yylval.v.string == NULL)
			errx(1, "yylex: strdup");
		return (STRING);
	}

#define allowed_in_string(x) \
	(isalnum(x) || (ispunct(x) && x != '(' && x != ')' && \
	x != '{' && x != '}' && x != '<' && x != '>' && \
	x != '!' && x != '=' && x != '/' && x != '#' && \
	x != ','))

	if (isalnum(c) || c == '[' || c == ':' || c == '_' || c == '*') {
		do {
			*p++ = c;
			if ((unsigned)(p-buf) >= sizeof(buf)) {
				yyerror("string too long");
				return (findeol());
			}
		} while ((c = lgetc(fin)) != EOF && (allowed_in_string(c)));
		lungetc(c);
		*p = '\0';
		if ((token = lookup(buf)) == STRING)
			if ((yylval.v.string = strdup(buf)) == NULL)
				errx(1, "yylex: strdup");
		return (token);
	}
	if (c == '\n') {
		yylval.lineno = lineno;
		lineno++;
	}
	if (c == EOF)
		return (0);
	return (c);
}

int
parse_config(char *filename, struct flowd_config *mconf)
{
	struct sym		*sym, *next;

	conf = mconf;

	TAILQ_INIT(&conf->listen_addrs);

	lineno = 1;
	errors = 0;

	if ((fin = fopen(filename, "r")) == NULL) {
		warn("%s", filename);
		return (-1);
	}
	infile = filename;

	yyparse();

	fclose(fin);

	/* Free macros and check which have not been used. */
	for (sym = TAILQ_FIRST(&symhead); sym != NULL; sym = next) {
		next = TAILQ_NEXT(sym, entry);
		if ((conf->opts & FLOWD_OPT_VERBOSE) && !sym->used)
			fprintf(stderr, "warning: macro \"%s\" not "
			    "used\n", sym->nam);
		if (!sym->persist) {
			free(sym->nam);
			free(sym->val);
			TAILQ_REMOVE(&symhead, sym, entry);
			free(sym);
		}
	}

	return (errors ? -1 : 0);
}

int
symset(const char *nam, const char *val, int persist)
{
	struct sym	*sym;

	for (sym = TAILQ_FIRST(&symhead); sym && strcmp(nam, sym->nam);
	    sym = TAILQ_NEXT(sym, entry))
		;	/* nothing */

	if (sym != NULL) {
		if (sym->persist == 1)
			return (0);
		else {
			free(sym->nam);
			free(sym->val);
			TAILQ_REMOVE(&symhead, sym, entry);
			free(sym);
		}
	}
	if ((sym = calloc(1, sizeof(*sym))) == NULL)
		return (-1);

	sym->nam = strdup(nam);
	if (sym->nam == NULL) {
		free(sym);
		return (-1);
	}
	sym->val = strdup(val);
	if (sym->val == NULL) {
		free(sym->nam);
		free(sym);
		return (-1);
	}
	sym->used = 0;
	sym->persist = persist;
	TAILQ_INSERT_TAIL(&symhead, sym, entry);
	return (0);
}

int
cmdline_symset(char *s)
{
	char	*sym, *val;
	int	ret;
	size_t	len;

	if ((val = strrchr(s, '=')) == NULL)
		return (-1);

	len = strlen(s) - strlen(val) + 1;
	if ((sym = malloc(len)) == NULL)
		errx(1, "cmdline_symset: malloc");

	strlcpy(sym, s, len);

	ret = symset(sym, val + 1, 1);
	free(sym);

	return (ret);
}

char *
symget(const char *nam)
{
	struct sym	*sym;

	TAILQ_FOREACH(sym, &symhead, entry)
		if (strcmp(nam, sym->nam) == 0) {
			sym->used = 1;
			return (sym->val);
		}
	return (NULL);
}

int
atoul(char *s, u_long *ulvalp)
{
	u_long	 ulval;
	char	*ep;

	errno = 0;
	ulval = strtoul(s, &ep, 0);
	if (s[0] == '\0' || *ep != '\0')
		return (-1);
	if (errno == ERANGE && ulval == ULONG_MAX)
		return (-1);
	*ulvalp = ulval;
	return (0);
}

