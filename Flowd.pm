use strict;
use warnings;

package Flowd::Store;

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
	die "unsupported version" unless $self->{version} == 0x00000001;
}

sub readflow {
	my $self = shift;

	return Flowd::FlowRec->new($self);
}

package Flowd::FlowRec;

my @fieldspec = (
#	  Field Flag	Field Name		Length
	[ 0x00000001,	"PROTO_FLAGS_TOS", 	4	],
	[ 0x00000002,	"AGENT_ADDR4", 		4	],
	[ 0x00000004,	"AGENT_ADDR6", 		16	],
	[ 0x00000008,	"SRCDST_ADDR4", 	8	],
	[ 0x00000010,	"SRCDST_ADDR6", 	32	],
	[ 0x00000020,	"GATEWAY_ADDR4", 	4	],
	[ 0x00000040,	"GATEWAY_ADDR6", 	16	],
	[ 0x00000080,	"SRCDST_PORT", 		4	],
	[ 0x00000100,	"PACKETS_OCTETS", 	16	],
	[ 0x00000200,	"IF_INDICES", 		4	],
	[ 0x00000400,	"AGENT_INFO", 		16	],
	[ 0x00000800,	"FLOW_TIMES", 		8	],
	[ 0x00001000,	"AS_INFO", 		12	],
	[ 0x00002000,	"FLOW_ENGINE_INFO", 	8	],
	[ 0x40000000,	"CRC32", 		4	]
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
	my $store = shift;
	my $hdr;
	my $r;
	my %fields = ();

	# Read initial flow header
	$r = read($store->{handle}, $hdr, 12);

	die "read($store->{filename}): $!" if not defined $r;
	die "early EOF on $store->{filename}" if $r < 12;

	foreach my $fspec (@fieldspec) {
		$fields{@$fspec[1]} = "";
		$r = read($store->{handle}, $fields{@$fspec[1]}, @$fspec[2]);
		die "read($store->{filename}): $!" if not defined $r;
		die "early EOF on $store->{filename}" if $r < @$fspec[2];
	}

	printf "%s\n", join(" ", keys(%fields));

	($self->{fields}, $self->{tag}, $self->{recv_secs})
		= unpack("NNN", $hdr);

}

return 1;
