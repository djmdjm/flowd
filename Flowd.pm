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

use strict;
use warnings;
use Math::BigInt;
use Socket;
use Socket6;
use Carp;

package Flowd;

use constant VERSION		=>	"0.4";

sub iso_time {
	my $timet = shift;
	my $utc = 0;
	my @tm;

	Carp::confess("missing argument") if not defined $timet;

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

	Carp::confess("missing argument") if not defined $t;

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

sub new {
	my $class = shift;
	my @args = (@_);

	my $self = {};
	bless($self, $class);

	$self->init(@args);

	return $self;
}

sub init {
	my $self = shift;
	my $filename = shift;
	my $fhandle;
	my $hdr;
	my $r;

	$self->{filename} = $filename;
	open($fhandle, "<$filename") or die "open($filename): $!";
	$self->{handle} = $fhandle;

	# Read initial header
	$r = read($self->{handle}, $hdr, 16);

	die "read($filename): $!" if not defined $r;
	die "early EOF on $filename" if $r < 16;

	($self->{magic}, $self->{version},
	 $self->{start_time}, $self->{flags}) = unpack("NNNN", $hdr);

	die "bad magic" unless $self->{magic} == 0x012cf047;
	die "unsupported version" unless $self->{version} == 0x00000002;
}

sub finish {
	my $self = shift;

	close($self->{handle});
	$self->{handle} = undef;
}

sub readflow {
	my $self = shift;

	return Flowd::Flow->new($self);
}

package Flowd::Flow;

use constant TAG		=> 0x00000001;
use constant RECV_TIME		=> 0x00000002;
use constant PROTO_FLAGS_TOS	=> 0x00000004;
use constant AGENT_ADDR4	=> 0x00000008;
use constant AGENT_ADDR6	=> 0x00000010;
use constant SRC_ADDR4		=> 0x00000020;
use constant SRC_ADDR6		=> 0x00000040;
use constant DST_ADDR4		=> 0x00000080;
use constant DST_ADDR6		=> 0x00000100;
use constant GATEWAY_ADDR4	=> 0x00000200;
use constant GATEWAY_ADDR6	=> 0x00000400;
use constant SRCDST_PORT	=> 0x00000800;
use constant PACKETS		=> 0x00001000;
use constant OCTETS		=> 0x00002000;
use constant IF_INDICES		=> 0x00004000;
use constant AGENT_INFO		=> 0x00008000;
use constant FLOW_TIMES		=> 0x00010000;
use constant AS_INFO		=> 0x00020000;
use constant FLOW_ENGINE_INFO	=> 0x00040000;
use constant CRC32		=> 0x40000000;

# Some useful combinations
use constant AGENT_ADDR		=> 0x00000018;
use constant SRC_ADDR		=> 0x00000060;
use constant DST_ADDR		=> 0x00000180;
use constant SRCDST_ADDR	=> 0x000001e0;
use constant GATEWAY_ADDR	=> 0x00000600;
use constant BRIEF		=> 0x000039ff;
use constant ALL		=> 0x4007ffff;

my @fieldspec = (
#	  Field Flag		Field Name		Length
	[ TAG,			"TAG",			4	],
	[ RECV_TIME,		"RECV_TIME",		4	],
	[ PROTO_FLAGS_TOS,	"PROTO_FLAGS_TOS",	4	],
	[ AGENT_ADDR4,		"AGENT_ADDR4",		4	],
	[ AGENT_ADDR6,		"AGENT_ADDR6",		16	],
	[ SRC_ADDR4,		"SRC_ADDR4",		4	],
	[ SRC_ADDR6,		"SRC_ADDR6",		16	],
	[ DST_ADDR4,		"DST_ADDR4",		4	],
	[ DST_ADDR6,		"DST_ADDR6",		16	],
	[ GATEWAY_ADDR4,	"GATEWAY_ADDR4",	4	],
	[ GATEWAY_ADDR6,	"GATEWAY_ADDR6",	16	],
	[ SRCDST_PORT,		"SRCDST_PORT",		4	],
	[ PACKETS,		"PACKETS",		8	],
	[ OCTETS,		"OCTETS",		8	],
	[ IF_INDICES,		"IF_INDICES",		4	],
	[ AGENT_INFO,		"AGENT_INFO",		16	],
	[ FLOW_TIMES,		"FLOW_TIMES",		8	],
	[ AS_INFO,		"AS_INFO",		8	],
	[ FLOW_ENGINE_INFO,	"FLOW_ENGINE_INFO",	8	],
	[ CRC32,		"CRC32",		4	]
);

sub new {
	my $class = shift;
	my @args = (@_);

	my $self = {};
	bless($self, $class);

	return undef if not $self->init(@args);

	return $self;
}

sub init {
	my $self = shift;
	my $store = shift;
	my $hdr;
	my $r;
	my %rawfields = ();
	my %fields = ();
	my $crc = Flowd::CRC32->new();

	# Read initial flow header
	$r = read($store->{handle}, $hdr, 4);

	die "read($store->{filename}): $!" if not defined $r;
	return 0 if $r == 0;
	die "early EOF on $store->{filename}" if $r < 4;

	$crc->update($hdr);

	$self->{fields} = \%fields;
	$self->{rawfields} = \%rawfields;

	($fields{fields}) = unpack("N", $hdr);

	# XXX - merge these two loops
	foreach my $fspec (@fieldspec) {
		next unless ($fields{fields} & @$fspec[0]);
		$rawfields{@$fspec[1]} = "";
		$r = read($store->{handle}, $rawfields{@$fspec[1]}, @$fspec[2]);
		die "read($store->{filename}): $!" if not defined $r;
		die "early EOF on $store->{filename}" if $r < @$fspec[2];
		$crc->update($rawfields{@$fspec[1]}) 
			unless @$fspec[1] eq "CRC32";
	}

	foreach my $field (keys %rawfields) {
		if ($field eq "TAG") {
			($fields{tag})
				= unpack "N", $rawfields{$field};
		} elsif ($field eq "RECV_TIME") {
			($fields{recv_secs})
				= unpack "N", $rawfields{$field};
		} elsif ($field eq "PROTO_FLAGS_TOS") {
			($fields{tcp_flags}, $fields{protocol},  $fields{tos})
				= unpack "CCC", $rawfields{$field};
		} elsif ($field eq "AGENT_ADDR4") {
			$fields{agent_addr_af} = Socket::PF_INET;
			$fields{agent_addr} = Socket6::inet_ntop(
			    Socket::PF_INET, $rawfields{$field});
		} elsif ($field eq "AGENT_ADDR6") {
			$fields{agent_addr_af} = Socket6::PF_INET6;
			$fields{agent_addr} = Socket6::inet_ntop(
			    Socket6::PF_INET6, $rawfields{$field});
		} elsif ($field eq "SRC_ADDR4") {
			$fields{src_addr_af} = Socket::PF_INET;
			$fields{src_addr} = Socket6::inet_ntop(
			    Socket::PF_INET, $rawfields{$field});
		} elsif ($field eq "SRC_ADDR6") {
			$fields{src_addr_af} = Socket6::PF_INET6;
			$fields{src_addr} = Socket6::inet_ntop(
			    Socket6::PF_INET6, $rawfields{$field});
		} elsif ($field eq "DST_ADDR4") {
			$fields{dst_addr_af} = Socket::PF_INET;
			$fields{dst_addr} = Socket6::inet_ntop(
			    Socket::PF_INET, $rawfields{$field});
		} elsif ($field eq "DST_ADDR6") {
			$fields{dst_addr_af} = Socket6::PF_INET6;
			$fields{dst_addr} = Socket6::inet_ntop(
			    Socket6::PF_INET6, $rawfields{$field});
		} elsif ($field eq "GATEWAY_ADDR4") {
			$fields{gateways_addr_af} = Socket::PF_INET;
			$fields{gateway_addr} = Socket6::inet_ntop(
			    Socket::PF_INET, $rawfields{$field});
		} elsif ($field eq "GATEWAY_ADDR6") {
			$fields{gateway_addr_af} = Socket6::PF_INET6;
			$fields{gateway_addr} = Socket6::inet_ntop(
			    Socket6::PF_INET6, $rawfields{$field});
		} elsif ($field eq "SRCDST_PORT") {
			($fields{src_port}, $fields{dst_port})
				= unpack "nn", $rawfields{$field};
		} elsif ($field eq "PACKETS") {
			(my $p1, my $p2)
				= unpack "NN", $rawfields{$field};
			if ($p1 != 0) {
				my $pp1 = Math::BigInt->new($p1);
				my $pp2 = Math::BigInt->new($p2);
				$fields{flow_packets} = $pp1->badd($pp2);
			} else {
				$fields{flow_packets} = $p2;
			}
		} elsif ($field eq "OCTETS") {
			(my $o1, my $o2)
				= unpack "NN", $rawfields{$field};
			if ($o1 != 0) {
				my $oo1 = Math::BigInt->new($o1);
				my $oo2 = Math::BigInt->new($o2);
				$fields{flow_octets} = $oo1->badd($oo2);
			} else {
				$fields{flow_octets} = $o2;
			}
		} elsif ($field eq "IF_INDICES") {
			($fields{if_index_in}, $fields{if_index_out})
				= unpack "nn", $rawfields{$field};
		} elsif ($field eq "AGENT_INFO") {
			($fields{sys_uptime_ms}, $fields{time_sec},
			 $fields{time_nanosec}, $fields{netflow_version}, 
			 my $pad) = unpack "NNNn", $rawfields{$field};
		} elsif ($field eq "FLOW_TIMES") {
			($fields{flow_start}, $fields{flow_finish})
				= unpack "NN", $rawfields{$field};
		} elsif ($field eq "AS_INFO") {
			($fields{src_as}, $fields{dst_as},
			 $fields{src_masklen}, $fields{dst_masklen}, my $pad)
				= unpack "nnCCn", $rawfields{$field};
		} elsif ($field eq "FLOW_ENGINE_INFO") {
			($fields{engine_type}, $fields{engine_id},
			 my $pad, $fields{flow_sequence})
			 	= unpack "CCnN", $rawfields{$field};
		} elsif ($field eq "CRC32") {
			($fields{crc}) = unpack "N", $rawfields{$field};
		}
	}

	die "Checksum mismatch"
		if defined $fields{crc} and $fields{crc} != $crc->final();

	return 1;
}

sub format
{
	my $self = shift;
	my $field_mask = shift;
	my $utc_flag = shift;
	my $fields = $self->{fields}->{fields} & $field_mask;

	my $ret = "";

	$ret .= "FLOW ";

	if ($fields & TAG) {
		$ret .= sprintf "tag %u ", $self->{fields}->{tag};
	}
	if ($fields & RECV_TIME) {
		$ret .= sprintf "recv_time %s ", 
		    Flowd::iso_time($self->{fields}->{recv_secs}, $utc_flag);
	}
	if ($fields & PROTO_FLAGS_TOS) {
		$ret .= sprintf "proto %u ", $self->{fields}->{protocol};
		$ret .= sprintf "tcpflags %02x ", $self->{fields}->{tcp_flags};
		$ret .= sprintf "tos %02x ", $self->{fields}->{tos};
	}
	if ($fields & AGENT_ADDR) {
		$ret .= sprintf "agent %s ", $self->{fields}->{agent_addr};
	}
	if ($fields & SRC_ADDR) {
		$ret .= sprintf "src %s", $self->{fields}->{src_addr};
		if ($fields & SRCDST_PORT) {
			$ret .= sprintf ":%u", $self->{fields}->{src_port};
		}
		$ret .= " ";
	}
	if ($fields & DST_ADDR) {
		$ret .= sprintf "dst %s", $self->{fields}->{dst_addr};
		if ($fields & SRCDST_PORT) {
			$ret .= sprintf ":%u", $self->{fields}->{dst_port};
		}
		$ret .= " ";
	}
	if ($fields & GATEWAY_ADDR) {
		$ret .= sprintf "gateway %s ", $self->{fields}->{gateway_addr};
	}
	if ($fields & PACKETS) {
		my $p = $self->{fields}->{flow_packets};
		$p =~ s/^\+//;
		$ret .= sprintf "packets %s ", $p;
	}
	if ($fields & OCTETS) {
		my $o = $self->{fields}->{flow_octets};
		$o =~ s/^\+//;
		$ret .= sprintf "octets %s ", $o;
	}
	if ($fields & IF_INDICES) {
		$ret .= sprintf "in_if %u ", $self->{fields}->{if_index_in};
		$ret .= sprintf "out_if %u ", $self->{fields}->{if_index_out};
	}
	if ($fields & AGENT_INFO) {
		$ret .= sprintf "sys_uptime_ms %s ",
		    Flowd::interval_time_ms($self->{fields}->{sys_uptime_ms});
		$ret .= sprintf "time_sec %s ",
		    Flowd::iso_time($self->{fields}->{time_sec}, $utc_flag);
		$ret .= sprintf "time_nanosec %u ",
		    $self->{fields}->{time_nanosec};
		$ret .= sprintf "netflow ver %u ",
			$self->{fields}->{netflow_version};
	}
	if ($fields & FLOW_TIMES) {
		$ret .= sprintf "flow_start %s ",
		    Flowd::interval_time_ms($self->{fields}->{flow_start});
		$ret .= sprintf "flow_finish %s ",
		    Flowd::interval_time_ms($self->{fields}->{flow_finish});
	}
	if ($fields & AS_INFO) {
		$ret .= sprintf "src_AS %u ", $self->{fields}->{src_as};
		$ret .= sprintf "src_masklen %u ",
		    $self->{fields}->{src_masklen};
		$ret .= sprintf "dst_AS %u ", $self->{fields}->{dst_as};
		$ret .= sprintf "dst_masklen %u ",
		    $self->{fields}->{dst_masklen};
	}
	if ($fields & FLOW_ENGINE_INFO) {
		$ret .= sprintf "engine_type %u ",
		    $self->{fields}->{engine_type};
		$ret .= sprintf "engine_id %u ", $self->{fields}->{engine_id};
		$ret .= sprintf "seq %u ", $self->{fields}->{flow_sequence};
	}
	if ($fields & CRC32) {
		$ret .= sprintf "crc32 %08x ", $self->{fields}->{crc};
	}

	return $ret;
}

package Flowd::CRC32;

my @crc32tab = (
	0x00000000, 0x77073096, 0xee0e612c, 0x990951ba,
	0x076dc419, 0x706af48f, 0xe963a535, 0x9e6495a3,
	0x0edb8832, 0x79dcb8a4, 0xe0d5e91e, 0x97d2d988,
	0x09b64c2b, 0x7eb17cbd, 0xe7b82d07, 0x90bf1d91,
	0x1db71064, 0x6ab020f2, 0xf3b97148, 0x84be41de,
	0x1adad47d, 0x6ddde4eb, 0xf4d4b551, 0x83d385c7,
	0x136c9856, 0x646ba8c0, 0xfd62f97a, 0x8a65c9ec,
	0x14015c4f, 0x63066cd9, 0xfa0f3d63, 0x8d080df5,
	0x3b6e20c8, 0x4c69105e, 0xd56041e4, 0xa2677172,
	0x3c03e4d1, 0x4b04d447, 0xd20d85fd, 0xa50ab56b,
	0x35b5a8fa, 0x42b2986c, 0xdbbbc9d6, 0xacbcf940,
	0x32d86ce3, 0x45df5c75, 0xdcd60dcf, 0xabd13d59,
	0x26d930ac, 0x51de003a, 0xc8d75180, 0xbfd06116,
	0x21b4f4b5, 0x56b3c423, 0xcfba9599, 0xb8bda50f,
	0x2802b89e, 0x5f058808, 0xc60cd9b2, 0xb10be924,
	0x2f6f7c87, 0x58684c11, 0xc1611dab, 0xb6662d3d,
	0x76dc4190, 0x01db7106, 0x98d220bc, 0xefd5102a,
	0x71b18589, 0x06b6b51f, 0x9fbfe4a5, 0xe8b8d433,
	0x7807c9a2, 0x0f00f934, 0x9609a88e, 0xe10e9818,
	0x7f6a0dbb, 0x086d3d2d, 0x91646c97, 0xe6635c01,
	0x6b6b51f4, 0x1c6c6162, 0x856530d8, 0xf262004e,
	0x6c0695ed, 0x1b01a57b, 0x8208f4c1, 0xf50fc457,
	0x65b0d9c6, 0x12b7e950, 0x8bbeb8ea, 0xfcb9887c,
	0x62dd1ddf, 0x15da2d49, 0x8cd37cf3, 0xfbd44c65,
	0x4db26158, 0x3ab551ce, 0xa3bc0074, 0xd4bb30e2,
	0x4adfa541, 0x3dd895d7, 0xa4d1c46d, 0xd3d6f4fb,
	0x4369e96a, 0x346ed9fc, 0xad678846, 0xda60b8d0,
	0x44042d73, 0x33031de5, 0xaa0a4c5f, 0xdd0d7cc9,
	0x5005713c, 0x270241aa, 0xbe0b1010, 0xc90c2086,
	0x5768b525, 0x206f85b3, 0xb966d409, 0xce61e49f,
	0x5edef90e, 0x29d9c998, 0xb0d09822, 0xc7d7a8b4,
	0x59b33d17, 0x2eb40d81, 0xb7bd5c3b, 0xc0ba6cad,
	0xedb88320, 0x9abfb3b6, 0x03b6e20c, 0x74b1d29a,
	0xead54739, 0x9dd277af, 0x04db2615, 0x73dc1683,
	0xe3630b12, 0x94643b84, 0x0d6d6a3e, 0x7a6a5aa8,
	0xe40ecf0b, 0x9309ff9d, 0x0a00ae27, 0x7d079eb1,
	0xf00f9344, 0x8708a3d2, 0x1e01f268, 0x6906c2fe,
	0xf762575d, 0x806567cb, 0x196c3671, 0x6e6b06e7,
	0xfed41b76, 0x89d32be0, 0x10da7a5a, 0x67dd4acc,
	0xf9b9df6f, 0x8ebeeff9, 0x17b7be43, 0x60b08ed5,
	0xd6d6a3e8, 0xa1d1937e, 0x38d8c2c4, 0x4fdff252,
	0xd1bb67f1, 0xa6bc5767, 0x3fb506dd, 0x48b2364b,
	0xd80d2bda, 0xaf0a1b4c, 0x36034af6, 0x41047a60,
	0xdf60efc3, 0xa867df55, 0x316e8eef, 0x4669be79,
	0xcb61b38c, 0xbc66831a, 0x256fd2a0, 0x5268e236,
	0xcc0c7795, 0xbb0b4703, 0x220216b9, 0x5505262f,
	0xc5ba3bbe, 0xb2bd0b28, 0x2bb45a92, 0x5cb36a04,
	0xc2d7ffa7, 0xb5d0cf31, 0x2cd99e8b, 0x5bdeae1d,
	0x9b64c2b0, 0xec63f226, 0x756aa39c, 0x026d930a,
	0x9c0906a9, 0xeb0e363f, 0x72076785, 0x05005713,
	0x95bf4a82, 0xe2b87a14, 0x7bb12bae, 0x0cb61b38,
	0x92d28e9b, 0xe5d5be0d, 0x7cdcefb7, 0x0bdbdf21,
	0x86d3d2d4, 0xf1d4e242, 0x68ddb3f8, 0x1fda836e,
	0x81be16cd, 0xf6b9265b, 0x6fb077e1, 0x18b74777,
	0x88085ae6, 0xff0f6a70, 0x66063bca, 0x11010b5c,
	0x8f659eff, 0xf862ae69, 0x616bffd3, 0x166ccf45,
	0xa00ae278, 0xd70dd2ee, 0x4e048354, 0x3903b3c2,
	0xa7672661, 0xd06016f7, 0x4969474d, 0x3e6e77db,
	0xaed16a4a, 0xd9d65adc, 0x40df0b66, 0x37d83bf0,
	0xa9bcae53, 0xdebb9ec5, 0x47b2cf7f, 0x30b5ffe9,
	0xbdbdf21c, 0xcabac28a, 0x53b39330, 0x24b4a3a6,
	0xbad03605, 0xcdd70693, 0x54de5729, 0x23d967bf,
	0xb3667a2e, 0xc4614ab8, 0x5d681b02, 0x2a6f2b94,
	0xb40bbe37, 0xc30c8ea1, 0x5a05df1b, 0x2d02ef8d
);

sub new {
	my $class = shift;
	my @args = (@_);

	my $self = {};
	bless($self, $class);

	$self->init(@args);

	return $self;
}

sub init {
	my $self = shift;
	$self->{crc} = 0;
}

sub update {
	my $self = shift;
	my $buf = shift;
	my $len = length($buf);
	my $i;

	for($i = 0; $i < $len; $i++) {
		my $c = unpack("C", substr($buf, $i, 1));
		$self->{crc} = $crc32tab[($self->{crc} ^ $c) & 0xff] ^
		    ($self->{crc} >> 8);
	}
	return $self->{crc};
}

sub final {
	my $self = shift;

	return $self->{crc};
}

return 1;
__END__
=head1 NAME

Flowd -- interface to flowd binary NetFlow logs

=head1 SYNOPSIS

  use Flowd;

  my $fh = Flowd->new($flowlog_filename);
  while (my $flow = $log->readflow()) {
          print $flow->format(Flowd::Flow::BRIEF, 0) . "\n";
  }
  $fh->finish();

=head1 DESCRIPTION

The Flowd package provides an interface to the flowd binary NetFlow storage
format.

=head1 BUGS

This documentation is very incomplete.

=head1 AUTHOR

Damien Miller <djm@mindrot.org>
