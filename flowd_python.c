/*
 * Copyright (c) 2004 Damien Miller <djm@mindrot.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <Python.h>
#include <netinet/in.h>
#include <sys/types.h>
#include "common.h"
#include "store.h"

RCSID("$Id$");

static PyObject *
flow_header_length(PyObject *self, PyObject *args)
{
	int version;

	version = STORE_VERSION;
	if (!PyArg_ParseTuple(args, "|k", &version))
		return (NULL);
	if (version != STORE_VERSION) {
		PyErr_SetString(PyExc_NotImplementedError,
		    "Unsupported store version");
		return (NULL);
	}
	return (PyInt_FromLong(sizeof(struct store_flow)));
}

static PyObject *
flow_length(PyObject *self, PyObject *args)
{
	u_char *buf;
	int version, len;

	version = STORE_VERSION;
	if (!PyArg_ParseTuple(args, "s#|k", &buf, &len, &version) ||
	    buf == NULL)
		return (NULL);
	if (version != STORE_VERSION) {
		PyErr_SetString(PyExc_NotImplementedError,
		    "Unsupported store version");
		return (NULL);
	}
	if (len < (ssize_t)sizeof(struct store_flow)) {
		PyErr_SetString(PyExc_ValueError,
		    "Supplied header is too short");
		return (NULL);
	}
	return (PyInt_FromLong(store_calc_flow_len((struct store_flow *)buf)));
}

static PyObject *
flow_deserialise(PyObject *self, PyObject *args)
{
	u_int32_t fields;
	int version, len, r;
	struct store_flow_complete flow;
	u_int8_t *buf;
	char ebuf[512], addr_buf[128];
	PyObject *ret, *field;

	version = STORE_VERSION;
	if (!PyArg_ParseTuple(args, "s#|k", &buf, &len, &version) ||
	    buf == NULL)
		return (NULL);
	if (version != STORE_VERSION) {
		PyErr_SetString(PyExc_NotImplementedError,
		    "Unsupported store version");
		return (NULL);
	}

	r = store_flow_deserialise(buf, len, &flow, ebuf, sizeof(ebuf));
	if (r != STORE_ERR_OK) {
		PyErr_SetString(PyExc_ValueError, ebuf);
		return (NULL);
	}

	fields = ntohl(flow.hdr.fields);

	if ((ret = PyDict_New()) == NULL)
		return (NULL);

	field = PyLong_FromUnsignedLong(fields);
	if (field == NULL)
		goto field_err;
	if (PyDict_SetItemString(ret, "fields", field))
		goto setitem_err;
	Py_DECREF(field);

	if (fields & STORE_FIELD_TAG) {
		field = PyLong_FromUnsignedLong(ntohl(flow.tag.tag));
		if (field == NULL)
			goto field_err;
		if (PyDict_SetItemString(ret, "tag", field))
			goto setitem_err;
		Py_DECREF(field);
	}
	if (fields & STORE_FIELD_RECV_TIME) {
		field = PyLong_FromUnsignedLong(ntohl(flow.recv_time.recv_secs));
		if (field == NULL)
			goto field_err;
		if (PyDict_SetItemString(ret, "recv_secs", field))
			goto setitem_err;
		Py_DECREF(field);
	}
	if (fields & STORE_FIELD_PROTO_FLAGS_TOS) {
		field = PyInt_FromLong(flow.pft.tcp_flags);
		if (field == NULL)
			goto field_err;
		if (PyDict_SetItemString(ret, "tcp_flags", field))
			goto setitem_err;
		Py_DECREF(field);
		field = PyInt_FromLong(flow.pft.protocol);
		if (field == NULL)
			goto field_err;
		if (PyDict_SetItemString(ret, "protocol", field))
			goto setitem_err;
		Py_DECREF(field);
		field = PyInt_FromLong(flow.pft.tos);
		if (field == NULL)
			goto field_err;
		if (PyDict_SetItemString(ret, "tos", field))
			goto setitem_err;
		Py_DECREF(field);
	}
	if (fields & (STORE_FIELD_AGENT_ADDR4|STORE_FIELD_AGENT_ADDR6)) {
		addr_ntop(&flow.agent_addr, addr_buf, sizeof(addr_buf));
		field = PyString_FromString(addr_buf);
		if (field == NULL)
			goto field_err;
		if (PyDict_SetItemString(ret, "agent_addr", field))
			goto setitem_err;
		Py_DECREF(field);
		field = PyInt_FromLong(flow.agent_addr.af);
		if (field == NULL)
			goto field_err;
		if (PyDict_SetItemString(ret, "agent_addr_af", field))
			goto setitem_err;
		Py_DECREF(field);
	}
	if (fields & (STORE_FIELD_SRC_ADDR4|STORE_FIELD_SRC_ADDR6)) {
		addr_ntop(&flow.src_addr, addr_buf, sizeof(addr_buf));
		field = PyString_FromString(addr_buf);
		if (field == NULL)
			goto field_err;
		if (PyDict_SetItemString(ret, "src_addr", field))
			goto setitem_err;
		Py_DECREF(field);
		field = PyInt_FromLong(flow.src_addr.af);
		if (field == NULL)
			goto field_err;
		if (PyDict_SetItemString(ret, "src_addr_af", field))
			goto setitem_err;
		Py_DECREF(field);
	}
	if (fields & (STORE_FIELD_DST_ADDR4|STORE_FIELD_DST_ADDR6)) {
		addr_ntop(&flow.dst_addr, addr_buf, sizeof(addr_buf));
		field = PyString_FromString(addr_buf);
		if (field == NULL)
			goto field_err;
		if (PyDict_SetItemString(ret, "dst_addr", field))
			goto setitem_err;
		Py_DECREF(field);
		field = PyInt_FromLong(flow.dst_addr.af);
		if (field == NULL)
			goto field_err;
		if (PyDict_SetItemString(ret, "dst_addr_af", field))
			goto setitem_err;
		Py_DECREF(field);
	}
	if (fields & (STORE_FIELD_GATEWAY_ADDR4|STORE_FIELD_GATEWAY_ADDR6)) {
		addr_ntop(&flow.gateway_addr, addr_buf, sizeof(addr_buf));
		field = PyString_FromString(addr_buf);
		if (field == NULL)
			goto field_err;
		if (PyDict_SetItemString(ret, "gateway_addr", field))
			goto setitem_err;
		Py_DECREF(field);
		field = PyInt_FromLong(flow.gateway_addr.af);
		if (field == NULL)
			goto field_err;
		if (PyDict_SetItemString(ret, "gateway_addr_af", field))
			goto setitem_err;
		Py_DECREF(field);
	}
	if (fields & STORE_FIELD_SRCDST_PORT) {
		field = PyInt_FromLong(ntohs(flow.ports.src_port));
		if (field == NULL)
			goto field_err;
		if (PyDict_SetItemString(ret, "src_port", field))
			goto setitem_err;
		Py_DECREF(field);
		field = PyInt_FromLong(ntohs(flow.ports.dst_port));
		if (field == NULL)
			goto field_err;
		if (PyDict_SetItemString(ret, "dst_port", field))
			goto setitem_err;
		Py_DECREF(field);
	}
	if (fields & STORE_FIELD_PACKETS) {
		field = PyLong_FromUnsignedLongLong(
		    store_ntohll(flow.packets.flow_packets));
		if (field == NULL)
			goto field_err;
		if (PyDict_SetItemString(ret, "flow_packets", field))
			goto setitem_err;
		Py_DECREF(field);
	}
	if (fields & STORE_FIELD_OCTETS) {
		field = PyLong_FromUnsignedLongLong(
		    store_ntohll(flow.octets.flow_octets));
		if (field == NULL)
			goto field_err;
		if (PyDict_SetItemString(ret, "flow_octets", field))
			goto setitem_err;
		Py_DECREF(field);
	}
	if (fields & STORE_FIELD_IF_INDICES) {
		field = PyInt_FromLong(ntohs(flow.ifndx.if_index_in));
		if (field == NULL)
			goto field_err;
		if (PyDict_SetItemString(ret, "if_index_in", field))
			goto setitem_err;
		Py_DECREF(field);
		field = PyInt_FromLong(ntohs(flow.ifndx.if_index_out));
		if (field == NULL)
			goto field_err;
		if (PyDict_SetItemString(ret, "if_index_out", field))
			goto setitem_err;
		Py_DECREF(field);
	}
	if (fields & STORE_FIELD_AGENT_INFO) {
		field = PyLong_FromUnsignedLong(
		    ntohl(flow.ainfo.sys_uptime_ms));
		if (field == NULL)
			goto field_err;
		if (PyDict_SetItemString(ret, "sys_uptime_ms", field))
			goto setitem_err;
		Py_DECREF(field);
		field = PyLong_FromUnsignedLong(ntohl(flow.ainfo.time_sec));
		if (field == NULL)
			goto field_err;
		if (PyDict_SetItemString(ret, "time_sec", field))
			goto setitem_err;
		Py_DECREF(field);
		field = PyLong_FromUnsignedLong(ntohl(flow.ainfo.time_nanosec));
		if (field == NULL)
			goto field_err;
		if (PyDict_SetItemString(ret, "time_nanosec", field))
			goto setitem_err;
		Py_DECREF(field);
		field = PyInt_FromLong(ntohs(flow.ainfo.netflow_version));
		if (field == NULL)
			goto field_err;
		if (PyDict_SetItemString(ret, "netflow_version", field))
			goto setitem_err;
		Py_DECREF(field);
	}
	if (fields & STORE_FIELD_FLOW_TIMES) {
		field = PyLong_FromUnsignedLong(ntohl(flow.ftimes.flow_start));
		if (field == NULL)
			goto field_err;
		if (PyDict_SetItemString(ret, "flow_start", field))
			goto setitem_err;
		Py_DECREF(field);
		field = PyLong_FromUnsignedLong(ntohl(flow.ftimes.flow_finish));
		if (field == NULL)
			goto field_err;
		if (PyDict_SetItemString(ret, "flow_finish", field))
			goto setitem_err;
		Py_DECREF(field);
	}
	if (fields & STORE_FIELD_AS_INFO) {
		field = PyInt_FromLong(ntohs(flow.asinf.src_as));
		if (field == NULL)
			goto field_err;
		if (PyDict_SetItemString(ret, "src_as", field))
			goto setitem_err;
		Py_DECREF(field);
		field = PyInt_FromLong(ntohs(flow.asinf.dst_as));
		if (field == NULL)
			goto field_err;
		if (PyDict_SetItemString(ret, "dst_as", field))
			goto setitem_err;
		Py_DECREF(field);
		field = PyInt_FromLong(flow.asinf.src_mask);
		if (field == NULL)
			goto field_err;
		if (PyDict_SetItemString(ret, "src_mask", field))
			goto setitem_err;
		Py_DECREF(field);
		field = PyInt_FromLong(flow.asinf.dst_mask);
		if (field == NULL)
			goto field_err;
		if (PyDict_SetItemString(ret, "dst_mask", field))
			goto setitem_err;
		Py_DECREF(field);
	}
	if (fields & STORE_FIELD_FLOW_ENGINE_INFO) {
		field = PyInt_FromLong(flow.finf.engine_type);
		if (field == NULL)
			goto field_err;
		if (PyDict_SetItemString(ret, "engine_type", field))
			goto setitem_err;
		Py_DECREF(field);
		field = PyInt_FromLong(flow.finf.engine_id);
		if (field == NULL)
			goto field_err;
		if (PyDict_SetItemString(ret, "engine_id", field))
			goto setitem_err;
		Py_DECREF(field);
		field = PyLong_FromUnsignedLong(htonl(flow.finf.flow_sequence));
		if (field == NULL)
			goto field_err;
		if (PyDict_SetItemString(ret, "flow_sequence", field))
			goto setitem_err;
		Py_DECREF(field);
	}
	if (fields & STORE_FIELD_CRC32) {
		field = PyLong_FromUnsignedLong(ntohl(flow.crc32.crc32));
		if (field == NULL)
			goto field_err;
		if (PyDict_SetItemString(ret, "crc", field))
			goto setitem_err;
		Py_DECREF(field);
	}

	return (ret);

 setitem_err:
	Py_DECREF(field);
 field_err:
	Py_DECREF(ret);
	return (NULL);
}

static int
sr_get_u64(PyObject *dict, const char *key, u_int64_t *val)
{
	unsigned long long ullval;
	PyObject *field;

	if ((field = PyDict_GetItemString(dict, key)) == NULL)
		return (0);

	if ((ullval = PyInt_AsUnsignedLongLongMask(field)) == ULLONG_MAX) {
		PyErr_Format(PyExc_TypeError,
		    "\"%s\" entry is not an integer", key);
		return (-1);
	}
	*val = ullval;
	return (1);
}

static int
sr_get_addr(PyObject *dict, const char *key, struct xaddr *val)
{
	PyObject *field;
	const char *addr;
	struct xaddr xa;

	if ((field = PyDict_GetItemString(dict, key)) == NULL)
		return (0);
	if ((addr = PyString_AsString(field)) == NULL) {
		PyErr_Format(PyExc_TypeError,
		    "\"%s\" entry is not a string", key);
		return (-1);
	}
	if (addr_pton(addr, &xa) == -1) {
		PyErr_Format(PyExc_ValueError,
		    "Invalid \"%s\" address", key);
		return (-1);
	}
	memcpy(val, &xa, sizeof(*val));
	return (1);
}

static PyObject *
flow_serialise(PyObject *self, PyObject *args)
{
	u_int32_t fields, mask;
	u_int64_t uv;
	int version, len, r;
	struct store_flow_complete flow;
	char ebuf[512];
	PyObject *flow_dict;
	struct xaddr addr;
	/* XXX: assume that a serialised flow will fit into a unpacked struct */
	u_int8_t flow_buf[sizeof(struct store_flow_complete)];

	version = STORE_VERSION;
	mask = 0xffffffff;
	if (!PyArg_ParseTuple(args, "O!|kk", &PyDict_Type, &flow_dict,
	    &mask, &version))
		return (NULL);
	if (version != STORE_VERSION) {
		PyErr_SetString(PyExc_NotImplementedError,
		    "Unsupported store version");
		return (NULL);
	}

	memset(&flow, 0, sizeof(flow));
	fields = 0;

#define U8_ENTRY(name, field, target) do { \
		if ((r = sr_get_u64(flow_dict, name, &uv)) == -1) \
			return (NULL); \
		if (r == 1) { \
			fields |= STORE_FIELD_##field; \
			if (uv > 0xff) { \
				PyErr_Format(PyExc_ValueError, \
				    "\"%s\" entry out of range", name); \
				return (NULL); \
			} \
			flow.target = uv & 0xff; \
		} \
	} while (0)
#define U16_ENTRY(name, field, target) do { \
		if ((r = sr_get_u64(flow_dict, name, &uv)) == -1) \
			return (NULL); \
		if (r == 1) { \
			fields |= STORE_FIELD_##field; \
			if (uv > 0xffff) { \
				PyErr_Format(PyExc_ValueError, \
				    "\"%s\" entry out of range", name); \
				return (NULL); \
			} \
			flow.target = htons(uv & 0xffff); \
		} \
	} while (0)
#define U32_ENTRY(name, field, target) do { \
		if ((r = sr_get_u64(flow_dict, name, &uv)) == -1) \
			return (NULL); \
		if (r == 1) { \
			fields |= STORE_FIELD_##field; \
			if (uv > 0xffffffff) { \
				PyErr_Format(PyExc_ValueError, \
				    "\"%s\" entry out of range", name); \
				return (NULL); \
			} \
			flow.target = htonl(uv & 0xffffffff); \
		} \
	} while (0)
#define U64_ENTRY(name, field, target) do { \
		if ((r = sr_get_u64(flow_dict, name, &uv)) == -1) \
			return (NULL); \
		if (r == 1) { \
			fields |= STORE_FIELD_##field; \
			flow.target = store_htonll(uv); \
		} \
	} while (0)
#define ADDR_ENTRY(name, field, target) do { \
		if ((r = sr_get_addr(flow_dict, name, &addr)) == -1) \
			return (NULL); \
		if (r == 1) { \
			if (addr.af == AF_INET) \
				fields |= STORE_FIELD_##field##4; \
			else if (addr.af == AF_INET6) \
				fields |= STORE_FIELD_##field##6; \
			else \
				return (NULL); \
			flow.target = addr; \
		} \
	} while (0)

	U32_ENTRY("tag", TAG, tag.tag);
	U32_ENTRY("recv_secs", RECV_TIME, recv_time.recv_secs);
	U8_ENTRY("tcp_flags", PROTO_FLAGS_TOS, pft.tcp_flags);
	U8_ENTRY("protocol", PROTO_FLAGS_TOS, pft.protocol);
	U8_ENTRY("tos", PROTO_FLAGS_TOS, pft.tos);
	ADDR_ENTRY("agent_addr", AGENT_ADDR, agent_addr);
	ADDR_ENTRY("src_addr", SRC_ADDR, src_addr);
	ADDR_ENTRY("dst_addr", DST_ADDR, dst_addr);
	ADDR_ENTRY("gateway_addr", GATEWAY_ADDR, gateway_addr);
	U16_ENTRY("src_port", SRCDST_PORT, ports.src_port);
	U16_ENTRY("dst_port", SRCDST_PORT, ports.dst_port);
	U64_ENTRY("flow_packets", PACKETS, packets.flow_packets);
	U64_ENTRY("flow_octets", OCTETS, octets.flow_octets);
	U16_ENTRY("if_index_in", IF_INDICES, ifndx.if_index_in);
	U16_ENTRY("if_index_out", IF_INDICES, ifndx.if_index_out);
	U32_ENTRY("sys_uptime_ms", AGENT_INFO, ainfo.sys_uptime_ms);
	U32_ENTRY("time_sec", AGENT_INFO, ainfo.time_sec);
	U32_ENTRY("time_nanosec", AGENT_INFO, ainfo.time_nanosec);
	U16_ENTRY("netflow_version", AGENT_INFO, ainfo.netflow_version);
	U32_ENTRY("flow_start", FLOW_TIMES, ftimes.flow_start);
	U32_ENTRY("flow_finish", FLOW_TIMES, ftimes.flow_finish);
	U16_ENTRY("src_as", AS_INFO, asinf.src_as);
	U16_ENTRY("dst_as", AS_INFO, asinf.dst_as);
	U8_ENTRY("src_mask", AS_INFO, asinf.src_mask);
	U8_ENTRY("dst_mask", AS_INFO, asinf.dst_mask);
	U8_ENTRY("engine_type", FLOW_ENGINE_INFO, finf.engine_type);
	U8_ENTRY("engine_id", FLOW_ENGINE_INFO, finf.engine_id);
	U32_ENTRY("flow_sequence", FLOW_ENGINE_INFO, finf.flow_sequence);

#undef U8_ENTRY
#undef U16_ENTRY
#undef U32_ENTRY
#undef U64_ENTRY
#undef ADDR_ENTRY

	fields &= mask;
	flow.hdr.fields = htonl(fields);

	if ((r = store_calc_flow_len(&flow.hdr)) < 0) {
		PyErr_SetString(PyExc_ValueError,
		    "Invalid field specification");
		return (NULL);
	}
	r = store_flow_serialise(&flow, flow_buf, sizeof(flow_buf), &len,
	    ebuf, sizeof(ebuf));
	if (r != STORE_ERR_OK) {
		PyErr_SetString(PyExc_ValueError, ebuf);
		return (NULL);
	}
	return (PyString_FromStringAndSize(flow_buf, len));
}


PyDoc_STRVAR(flowd_doc,
"This module performs conversions from binary flowd logs to Python\n"
"dictionaries. This is used by the flowd.py module to provide a high-level\n"
"API to flowd logs. Unless you really have a need, just use flowd.py");

static PyMethodDef flowd_methods[] = {
	{ "header_len",		flow_header_length,	METH_VARARGS,
	  PyDoc_STR("Return the length of a flow record header") },
	{ "flow_len",		flow_length,		METH_VARARGS,
	  PyDoc_STR("Calcuate the length of a flow record, given its header") },
	{ "deserialise",	flow_deserialise,	METH_VARARGS,
	  PyDoc_STR("Convert a binary flow log record into a dict of fields") },
	{ "serialise",		flow_serialise,		METH_VARARGS,
	  PyDoc_STR("Convert a dict flow record into a binary log record") },
	{ NULL, NULL, 0, NULL}	/* sentinel */
};

PyMODINIT_FUNC initflowd_serialiser(void);

PyMODINIT_FUNC
initflowd_serialiser(void)
{
	PyObject *m;

	m = Py_InitModule3("flowd_serialiser", flowd_methods, flowd_doc);
	PyModule_AddStringConstant(m, "__version__", PROGVER);
}
