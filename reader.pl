#!/usr/bin/perl

use strict;
use warnings;

use Flowd;

sub usage
{
	printf STDERR "reader.pl (Flowd.pm version %s)\n", Flowd::VERSION;
	printf STDERR "Usage: reader.pl [flowd-store]\n";
	exit 1;
}

usage() unless (defined $ARGV[0]);

foreach my $ffile (@ARGV) {
	my $log = Flowd->new($ffile);
	
	printf "LOGFILE %s started at %s\n",
	    $ffile, Flowd::iso_time($log->{start_time}, 0);
	
	while (my $flow = $log->readflow()) {
		print $flow->format(Flowd::Flow::BRIEF, 0);
		print "\n";
	}
}
