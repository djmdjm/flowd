#!/usr/bin/perl

use strict;
use warnings;

use Flowd;

sub iso_time {
	my $timet = shift;
	my $utc = 0;
	my @tm;

	@tm = localtime($timet) unless $utc;
	@tm = gmtime($timet) if $utc;

	return sprintf("%04u-%02u-%02uT%02u:%02u:%02u", 
	    1900 + $tm[5], 1 + $tm[4], $tm[3], $tm[2], $tm[1], $tm[0]);
}

sub interval_time {
	my $t = shift;
	my @ivs = (
		[ "m", 60 ], [ "h", 60 ], [ "d", 24 ], 
		[ "w", 7 ], [ "y", 52 ] 
	);
	my $ret = "s";

	foreach my $iv (@ivs) {
		$ret = sprintf "%u%s", $t % @$iv[1], $ret;
		$t = int($t / @$iv[1]);
		last if $t <= 0;
		$ret = @$iv[0] . $ret;
	}
	return $ret;
}

sub interval_time_ms
{
	my $tms = shift;

	return sprintf "%s.%03u", interval_time($tms / 1000), $tms % 1000,	
}

die "Usage: reader.pl [flowd-store]\n" unless (defined $ARGV[0]);

foreach my $ffile (@ARGV) {
	my $log = Flowd::Store->new($ffile);
	
	printf "LOGFILE %s started at %s\n",
	    $ffile, iso_time($log->{start_time}, 0);
	
	while (my $flow = $log->readflow()) {
		print $flow->format(Flowd::Flow::BRIEF, 0);
		print "\n";
	}
}
