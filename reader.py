#!/usr/bin/env python

# Copyright (c) 2004 Damien Miller <djm@mindrot.org>
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

# $Id$

# This intended to be an example of the flowd package API more than a usable
# application

import flowd
import sys
import getopt

def usage():
	print >> sys.stderr, "reader.pl (flowd.py version %s)" % flowd.VERSION
	print >> sys.stderr, "Usage: reader.pl [options] [flowd-store]";
	print >> sys.stderr, "Options:";
	print >> sys.stderr, "      -h       Display this help";
	print >> sys.stderr, "      -v       Print all flow information";
	print >> sys.stderr, "      -u       Print dates in UTC timezone";
	sys.exit(1);

def main():
	verbose = 0
	utc = 0

	try:
		opts, args = getopt.getopt(sys.argv[1:], 'huv')
	except getopt.GetoptError:
		print >> sys.stderr, "Invalid commandline arguments"
		usage()

	for o, a in opts:
		if o in ('-h', '--help'):
			usage()
			sys.exit(0)
		if o in ('-v', '--verbose'):
			verbose = 1
			continue
		if o in ('-u', '--utc'):
			utc = 1
			continue

	if len(args) == 0:
		print >> sys.stderr, "No logfiles specified"
		usage()

	if verbose:
		mask = flowd.flow.ALL
	else:
		mask = flowd.flow.BRIEF

	for ffile in args:
		flog = flowd.log(ffile)
		try:
			print "LOGFILE " + ffile + " started at " + \
			    flowd.iso_time(flog.start_time, utc = utc)
		except IOError:
			break;

		while 1:
			flow = flog.readflow()
			if flow is None:
				break
			try:
				print flow.format(field_mask = mask, utc = utc)
			except IOError:
				break;

		flog.finish()

if __name__ == '__main__': main()
