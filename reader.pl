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
		printf "FLOW tag %u %s ", $flow->{fields}->{tag},
		    iso_time($flow->{fields}->{recv_time}, 0);
		printf "proto %u ", $flow->{fields}->{protocol}
			if defined $flow->{fields}->{protocol};
		printf "tcpflags %02x ", $flow->{fields}->{tcp_flags}
			if defined $flow->{fields}->{tcp_flags};
		printf "tos %02x ", $flow->{fields}->{tos}
			if defined $flow->{fields}->{tos};
		printf "agent %s ", $flow->{fields}->{agent_addr}
			if defined $flow->{fields}->{agent_addr};
		printf "src %s", $flow->{fields}->{src_addr}
			if defined $flow->{fields}->{src_addr};
		printf ":%u", $flow->{fields}->{src_port}
			if defined $flow->{fields}->{src_port};
		printf " ";
		printf "dst %s", $flow->{fields}->{dst_addr}
			if defined $flow->{fields}->{dst_addr};
		printf ":%u", $flow->{fields}->{dst_port}
			if defined $flow->{fields}->{dst_port};
		printf " ";
		printf "gateway %s ", $flow->{fields}->{gateway_addr}
			if defined $flow->{fields}->{gateway_addr};
		printf "packets %s ", $flow->{fields}->{flow_packets}
			if defined $flow->{fields}->{flow_packets};
		printf "octets %s ", $flow->{fields}->{flow_octets}
			if defined $flow->{fields}->{flow_octets};
		printf "in_if %u ", $flow->{fields}->{if_index_in}
			if defined $flow->{fields}->{if_index_in};
		printf "in_out %u ", $flow->{fields}->{if_index_out}
			if defined $flow->{fields}->{if_index_out};
		printf "sys_uptime_ms %s ",
		    interval_time_ms($flow->{fields}->{sys_uptime_ms})
			if defined $flow->{fields}->{sys_uptime_ms};
		printf "time_sec %s ", iso_time($flow->{fields}->{time_sec})
			if defined $flow->{fields}->{time_sec};
		printf "time_nanosec %u ", $flow->{fields}->{time_nanosec}
			if defined $flow->{fields}->{time_nanosec};
		printf "netflow ver %u ", $flow->{fields}->{netflow_version}
			if defined $flow->{fields}->{netflow_version};
		printf "flow_start %s ",
		    interval_time_ms($flow->{fields}->{flow_start})
			if defined $flow->{fields}->{flow_start};
		printf "flow_finish %s ",
		    interval_time_ms($flow->{fields}->{flow_finish})
			if defined $flow->{fields}->{flow_finish};
		printf "src_AS %u ", $flow->{fields}->{src_as}
			if defined $flow->{fields}->{src_as};
		printf "src_masklen %u ", $flow->{fields}->{src_masklen}
			if defined $flow->{fields}->{src_masklen};
		printf "dst_AS %u ", $flow->{fields}->{dst_as}
			if defined $flow->{fields}->{dst_as};
		printf "dst_masklen %u ", $flow->{fields}->{dst_masklen}
			if defined $flow->{fields}->{dst_masklen};
		printf "engine_type %u ", $flow->{fields}->{engine_type}
			if defined $flow->{fields}->{engine_type};
		printf "engine_id %u ", $flow->{fields}->{engine_id}
			if defined $flow->{fields}->{engine_id};
		printf "seq %u ", $flow->{fields}->{flow_sequence}
			if defined $flow->{fields}->{flow_sequence};
		printf "crc32 %08x ", $flow->{fields}->{crc}
			if defined $flow->{fields}->{crc};

		print "\n";
	}
}
