#!/usr/bin/perl

use strict;
use warnings;

use Flowd;

die "Usage: reader.pl [flowd-store]\n" unless (defined $ARGV[0]);

my $flowlog = Flowd::Store->new($ARGV[0]);
my $flow = $flowlog->readflow();

print "%$flowlog\n";
print "%$flow\n";


