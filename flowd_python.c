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
	if (len < sizeof(struct store_flow)) {
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
		if (PyDict_SetItemString(ret, "src_mask", field))
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
	  PyDoc_STR("Convert a serialised flow record into a dict of fields") },
	{ NULL, NULL, 0, NULL}	/* sentinel */
};

PyMODINIT_FUNC
initflowd_serialiser(void)
{
	PyObject *m;

	m = Py_InitModule3("flowd_serialiser", flowd_methods, flowd_doc);
	PyModule_AddStringConstant(m, "__version__", PROGVER);
}
