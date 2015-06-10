This is flowd, a NetFlow collector daemon intended to be small, fast and
secure. It works well with hardware flow probes (e.g. routers) softflowd[1](1.md),
pfflowd[2](2.md), and other software agents that export NetFlow v.1, v.5, v.7 or
v.9 datagrams.

It features some basic filtering to limit or tag the flows that are
recorded and is privilege separated, to limit security exposure from
bugs in flowd itself. Flowd is IPv6 capable - supporting flow export via
IPv6 transport and NetFlow v.9 IPv6 flow records. It also supports reception
of flow datagrams sent to multicast groups, allowing one to build redundant
flow gathering systems.

flowd does not try to do anything beyond accepting NetFlow packets and
writing them to disk. In particular, it does not do any analysis and it
doesn't support storage into SQL databases. These tasks are left (in
typical Unix fashion) to separate programs. Some example tools (including
one to store flows in a SQL database) are provided in the tools/ directory.

At present, flowd is considered stable enough for production deployment.
Some more features are planned before the 1.0 release (see the TODO file
if you want to help), but everything that is documented should be working
now. Please report any problems to djm@mindrot.org. Bugs may also be reported
using the Bugzilla at http://bugzilla.mindrot.org/

flowd stores records on disk in a compact binary format, see store.h
for a specification in the form of a C header file. Perl, Python and C
APIs are provided to managing the log files that flowd creates. Example
applications are flowd-reader.c, reader.pl and reader.py. More useful
applications live in the tools/ directory, please refer to the
tools/README.tools file for an explanation of what they are. These example
apps will require that the relevant Perl/Python modules are installed as
described in the INSTALL document.

This on-disk format is a parametised format capable of storing a
superset of NetFlow v.5, including the most common records from NetFlow
v.9. Exactly which components of the NetFlow records actually get
written to disk may be specified at runtime, so the logs can be made
quite compact by excluding information that is uninteresting to you.
An optional, per-record CRC32 checksum is provided to detect log
corruption. Efforts are made to ensure that flows are written atomically
to disk, and backed out when a write fails.

At present, flowd supports NetFlow v.1, v.5, v.7 and v.9 packet formats
over both IPv4 and IPv6 transports. Future plans include sflow and IETF
IPFIX protocol support (when it is finalised). See the TODO file in
this distribution for more information (and more interesting projects if
you are a prospective developer)

flowd is tested on OpenBSD and Linux. It may work on other platforms,
but will likely need some adjusting. Please refer to the PLATFORMS file
for detailed notes on platform support and testing.

Large parts of this code have been shamelessly taken from OpenBSD, in
particular bgpd (the configuration parser) and OpenSSH (the privsep
fd passing and CRC32 code), sudo and libc. All of this code is under
BSD-like licenses, but read the LICENSE file for details.