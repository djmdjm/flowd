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

VERSION = "0.8.5"

import struct
import time
import socket
import sys
import flowd_serialiser

def iso_time(secs, utc = 0):
	if utc:
		tm = time.gmtime(secs)
	else:
		tm = time.localtime(secs)

	return "%04u-%02u-%02uT%02u:%02u:%02u" % tm[:6]

def interval_time(t):
	intervals = [	[ "s", 60 ], [ "m", 60 ], [ "h", 24 ],
			[ "d", 7 ], [ "w", 52 ]]
	ret = ""
	for interval in intervals:
		r = t % interval[1]
		t = int(t / interval[1])
		if r != 0 or interval[0] == "s":
			ret = "%u%s%s" % (r, interval[0], ret)
	if t > 0:
		ret = "%uy%s", (t, ret)

	return ret


def interval_time_ms(tms):
	return "%s.%03u" % ( interval_time(int(tms / 1000)), tms % 1000 )

class log:
	def __init__(self, path, mode = "r", start_time = None):
		self.path = path
		self.mode = mode
		if mode == "r":
			self.flow_file = open(path, "rb")
			# Read header
			hdr = self.flow_file.read(16)
			if len(hdr) != 16:
				raise ValueError, "Short read on flow header"
			(self.magic, self.version, self.start_time, \
			 self.flags) = struct.unpack(">IIII", hdr)

			if self.magic != 0x012cf047:
				raise ValueError, "Bad magic"
			if self.version != 0x00000002:
				raise ValueError, "Unsupported version"
		elif mode == "w" or mode == "a":
			self.flow_file = open(path, mode + "b")
			self.flow_file.seek(0, 2)
			if self.flow_file.tell() > 0:
				return

			# Write header
			self.magic = 0x012cf047
			self.version = 0x02
			self.flags = 0x00
			self.start_time = start_time
			if start_time is None:
				self.start_time = int(time.time())
			hdr = struct.pack(">IIII", self.magic, self.version, \
			    self.start_time, self.flags)
			if len(hdr) != 16:
				raise ValueError, "Internal error: bad header"
			self.flow_file.write(hdr)
			self.flow_file.flush()
		else:
			raise ValueError, "Invalid mode value";

	def finish(self):
		self.flow_file.close()
		self.flow_file = None

	def readflow(self):
		try:
			f = flow()
			f.from_file(self.flow_file)
		except EOFError:
			f = None
		return f

	def writeflow(self, flow):
		flow.to_file(self.flow_file)

class flow:
	TAG			= 0x00000001
	RECV_TIME		= 0x00000002
	PROTO_FLAGS_TOS		= 0x00000004
	AGENT_ADDR4		= 0x00000008
	AGENT_ADDR6		= 0x00000010
	SRC_ADDR4		= 0x00000020
	SRC_ADDR6		= 0x00000040
	DST_ADDR4		= 0x00000080
	DST_ADDR6		= 0x00000100
	GATEWAY_ADDR4		= 0x00000200
	GATEWAY_ADDR6		= 0x00000400
	SRCDST_PORT		= 0x00000800
	PACKETS			= 0x00001000
	OCTETS			= 0x00002000
	IF_INDICES		= 0x00004000
	AGENT_INFO		= 0x00008000
	FLOW_TIMES		= 0x00010000
	AS_INFO			= 0x00020000
	FLOW_ENGINE_INFO	= 0x00040000
	CRC32			= 0x40000000

	# Some useful combinations
	AGENT_ADDR		= 0x00000018
	SRC_ADDR		= 0x00000060
	DST_ADDR		= 0x00000180
	SRCDST_ADDR		= 0x000001e0
	GATEWAY_ADDR		= 0x00000600
	BRIEF			= 0x000039ff
	ALL			= 0x4007ffff

	def __init__(self):
		self.fields = { "fields" : 0 }

	def from_file(self, flow_file):
		# Read flow header
		needlen = flowd_serialiser.header_len()
		hdr = flow_file.read(needlen)
		if len(hdr) == 0:
			raise EOFError
		if len(hdr) != needlen:
			raise ValueError, "Short read on flow header"

		needlen = flowd_serialiser.flow_len(hdr)
		flow = flow_file.read(needlen)
		if len(flow) == 0:
			raise EOFError
		if len(flow) != needlen:
			raise ValueError, "Short read on flow data"

		self.fields = flowd_serialiser.deserialise(hdr + flow)

	def to_file(self, flow_file, field_mask = 0xffffffffL):
		flow = flowd_serialiser.serialise(self.fields, field_mask)
		flow_file.write(flow)
		flow_file.flush()

	def format(self, field_mask = BRIEF, utc = 0):
		fields = self.fields["fields"] & field_mask
		ret = "FLOW "

		if fields & self.__class__.TAG != 0:
			ret = ret + "tag %u " % self.fields["tag"]
		if fields & self.__class__.RECV_TIME != 0:
			ret = ret + "recv_time %s " % \
			    iso_time(self.fields["recv_secs"], utc)
		if fields & self.__class__.PROTO_FLAGS_TOS != 0:
			ret = ret + "proto %u " % self.fields["protocol"]
			ret = ret + "tcpflags %02x " % self.fields["tcp_flags"]
			ret = ret + "tos %02x " % self.fields["tos"]
		if fields & self.__class__.AGENT_ADDR != 0:
			ret = ret + "agent [%s] " % self.fields["agent_addr"]
		if fields & self.__class__.SRC_ADDR != 0:
			ret = ret + "src [%s]" % self.fields["src_addr"];
			if fields & self.__class__.SRCDST_PORT != 0:
				ret = ret + ":%u" % self.fields["src_port"];
			ret = ret + " ";
		if fields & self.__class__.DST_ADDR != 0:
			ret = ret + "dst [%s]" % self.fields["dst_addr"];
			if fields & self.__class__.SRCDST_PORT != 0:
				ret = ret + ":%u" % self.fields["dst_port"];
			ret = ret + " ";
		if fields & self.__class__.GATEWAY_ADDR != 0:
			ret = ret + "gateway [%s] " % \
			    self.fields["gateway_addr"];
		if fields & self.__class__.PACKETS != 0:
			ret = ret + "packets %s " % self.fields["flow_packets"];
		if fields & self.__class__.OCTETS != 0:
			ret = ret + "octets %s " % self.fields["flow_octets"];
		if fields & self.__class__.IF_INDICES != 0:
			ret = ret + "in_if %u " % self.fields["if_index_in"];
			ret = ret + "out_if %u " % self.fields["if_index_out"];
		if fields & self.__class__.AGENT_INFO != 0:
			ret = ret + "sys_uptime_ms %s " % \
			    interval_time_ms(self.fields["sys_uptime_ms"]);
			ret = ret + "time_sec %s " % \
			    iso_time(self.fields["time_sec"], utc);
			ret = ret + "time_nanosec %u " % \
			    self.fields["time_nanosec"];
			ret = ret + "netflow ver %u " % \
				self.fields["netflow_version"];
		if fields & self.__class__.FLOW_TIMES != 0:
			ret = ret + "flow_start %s " % \
			    interval_time_ms(self.fields["flow_start"]);
			ret = ret + "flow_finish %s " % \
			    interval_time_ms(self.fields["flow_finish"]);
		if fields & self.__class__.AS_INFO != 0:
			ret = ret + "src_AS %u " % self.fields["src_as"];
			ret = ret + "src_masklen %u " % \
			    self.fields["src_masklen"];
			ret = ret + "dst_AS %u " % self.fields["dst_as"];
			ret = ret + "dst_masklen %u " % \
			    self.fields["dst_masklen"];
		if fields & self.__class__.FLOW_ENGINE_INFO != 0:
			ret = ret + "engine_type %u " % \
			    self.fields["engine_type"];
			ret = ret + "engine_id %u " % self.fields["engine_id"];
			ret = ret + "seq %u " % self.fields["flow_sequence"];
		if fields & self.__class__.CRC32 != 0:
			ret = ret + "crc32 %08x " % self.fields["crc"];

		return ret;
