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

# This intended to be an example of the Flowd package API more than a usable
# application

import flowd
import sys
import getopt

def usage():
	print >> sys.stderr, "reader.pl (flowd.py version %s)" % flowd.VERSION
	print >> sys.stderr, "Usage: reader.pl [flowd-store]";
	sys.exit(1);

def main():
	verbose = 0

	try:
		opts, args = getopt.getopt(sys.argv[1:], 'hv')
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

	if len(args) == 0:
		print >> sys.stderr, "No logfiles specified"
		usage()

	for ffile in args:
		flog = flowd.log(ffile)
		print "LOGFILE " + ffile + " started at " + \
		    flowd.iso_time(flog.start_time)
		print flog.start_time

		while 1:
			flow = flog.readflow()
			print flow.fields
			break
			
#	while (my $flow = $log->readflow()) {
#		print $flow->format(Flowd::Flow::BRIEF, 0);
#		print "\n";
#	}
#	$log->finish();
#}

if __name__ == '__main__': main()
