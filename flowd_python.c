/*
 * Copyright (c) 2004,2005 Damien Miller <djm@mindrot.org>
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

#include "Python.h"
#include "structmember.h"
#include "store.h"

/* $Id$ */

/* Prototypes */
PyMODINIT_FUNC initflowd(void);
struct _FlowLogObject;
struct _FlowLogIterObject;
static struct _FlowLogIterObject *newFlowLogIterObject(struct _FlowLogObject *);

/* ------------------------------------------------------------------------ */

/* Flows*/

typedef struct {
	PyObject_HEAD
	PyObject *user_attr;	/* User-specified attributes */
	PyObject *octets;	/* bah. python >2.5 lacks T_LONGLONG */
	PyObject *packets;	/* ditto */
	char *agent_addr;
	char *src_addr;
	char *dst_addr;
	char *gateway_addr;
	struct store_flow_complete flow;
} FlowObject;

static PyTypeObject Flow_Type;

static FlowObject *
newFlowObject(void)
{
	FlowObject *self;

	self = PyObject_New(FlowObject, &Flow_Type);
	if (self == NULL)
		return NULL;

	self->octets = Py_None;
	Py_INCREF(Py_None);
	self->packets = Py_None;
	Py_INCREF(Py_None);
	self->user_attr = PyDict_New();

	if (self->user_attr == NULL) {
		/* Flow_dealloc will clean up for us */
		Py_XDECREF(self);
		return (NULL);		
	}

	return self;
}

static FlowObject *
newFlowObject_from_flow(struct store_flow_complete *flow)
{
	FlowObject *self;
	char addr_buf[128];

	/* Sanity check */
	if (flow == NULL)
		return NULL;

	self = PyObject_New(FlowObject, &Flow_Type);
	if (self == NULL)
		return NULL;

	self->user_attr = NULL;
	self->src_addr = self->dst_addr = NULL;
	self->agent_addr = self->gateway_addr = NULL;
	memcpy(&self->flow, flow, sizeof(self->flow));

	store_swab_flow(&self->flow, 0);

#define FL_ADDR(addr, which) do { \
	if ((self->flow.hdr.fields & STORE_FIELD_##which) != 0) { \
		if (addr_ntop(&self->flow.addr, addr_buf, \
		    sizeof(addr_buf)) != -1) \
		self->addr = strdup(addr_buf); \
	} } while (0)

	FL_ADDR(src_addr, SRC_ADDR);
	FL_ADDR(dst_addr, DST_ADDR);
	FL_ADDR(agent_addr, AGENT_ADDR);
	FL_ADDR(gateway_addr, GATEWAY_ADDR);

#undef FL_ADDR
	self->octets = PyLong_FromUnsignedLongLong(
		    self->flow.octets.flow_octets);
	self->packets = PyLong_FromUnsignedLongLong(
		    self->flow.packets.flow_packets);
	self->user_attr = PyDict_New();

	if (self->user_attr == NULL || self->octets == NULL ||
	    self->packets == NULL) {
		/* Flow_dealloc will clean up for us */
		Py_XDECREF(self);
		return (NULL);		
	}

	return self;
}

static int
flowobj_normalise(FlowObject *f)
{
	if (f->octets != NULL)
		f->flow.octets.flow_octets = PyLong_AsUnsignedLongLong(
		    f->octets);
	if (f->packets != NULL)
		f->flow.packets.flow_packets = PyLong_AsUnsignedLongLong(
		    f->packets);

#define FL_ADDR(addr, tag) do { \
	if (f->addr != NULL && *f->addr != '\0') { \
		if (addr_pton(f->addr, &f->flow.addr) == -1) { \
			PyErr_SetString(PyExc_ValueError, \
			    "Invalid \""#addr"\""); \
			return (-1); \
		} \
		f->flow.hdr.fields |= STORE_FIELD_##tag; \
	} else { \
		f->flow.hdr.fields &= ~STORE_FIELD_##tag; \
	} } while (0)

	FL_ADDR(src_addr, SRC_ADDR);
	FL_ADDR(dst_addr, DST_ADDR);
	FL_ADDR(agent_addr, AGENT_ADDR);
	FL_ADDR(gateway_addr, GATEWAY_ADDR);

#undef FL_ADDR

	return (0);
}

static FlowObject *
newFlowObject_from_blob(u_int8_t *buf, u_int len)
{
	struct store_flow_complete flow;
	char ebuf[512];

	/* Sanity check */
	if (buf == NULL || len == 0 || len > 8192)
		return NULL;

	if (store_flow_deserialise(buf, len, &flow, ebuf,
	    sizeof(ebuf)) != STORE_ERR_OK) {
		PyErr_SetString(PyExc_ValueError, ebuf);
		return (NULL);
	}

	return newFlowObject_from_flow(&flow);
}

/* Flow methods */

static void
Flow_dealloc(FlowObject *self)
{
	Py_XDECREF(self->user_attr);
	Py_XDECREF(self->octets);
	Py_XDECREF(self->packets);
	if (self->src_addr != NULL)
		free(self->src_addr);
	if (self->dst_addr != NULL)
		free(self->dst_addr);
	if (self->agent_addr != NULL)
		free(self->agent_addr);
	if (self->gateway_addr != NULL)
		free(self->gateway_addr);
	PyObject_Del(self);
}

PyDoc_STRVAR(flow_format_doc,
"Flow.format(utc = 0, mask = flowd.DISPLAY_BRIEF) -> String\n\
\n\
Format a flow to a string.\n\
");

static PyObject *
flow_format(FlowObject *self, PyObject *args, PyObject *kw_args)
{
	static char *keywords[] = { "utc", "mask", NULL };
	char buf[1024];
	int utcflag = 0;
	unsigned long mask = STORE_DISPLAY_BRIEF;

	if (!PyArg_ParseTupleAndKeywords(args, kw_args, "|ik:format", keywords,
	    &utcflag, &mask))
		return NULL;

	if (flowobj_normalise(self) == -1)
		return (NULL);

	store_format_flow(&self->flow, buf, sizeof(buf), utcflag, mask, 1);

	return PyString_FromString(buf);
}

PyDoc_STRVAR(flow_serialise_doc,
"Flow.serialise() -> String\n\
\n\
Format convert a flow object to a binary representation.\n\
");

static PyObject *
flow_serialise(FlowObject *self)
{
	char buf[1024], ebuf[512];
	struct store_flow_complete flow;
	int len;

	if (flowobj_normalise(self) == -1)
		return (NULL);

	memcpy(&self->flow, &flow, sizeof(flow));
	store_swab_flow(&flow, 1);
	
	if (store_flow_serialise(&flow, buf, sizeof(buf), &len , ebuf,
	    sizeof(ebuf)) != STORE_ERR_OK) {
		PyErr_SetString(PyExc_ValueError, ebuf);
		return (NULL);
	}

	return PyString_FromStringAndSize(buf, len);
}

static PyMethodDef Flow_methods[] = {
	{"format",	(PyCFunction)flow_format,	METH_VARARGS|METH_KEYWORDS,	flow_format_doc		},
	{"serialise",	(PyCFunction)flow_serialise,	0,				flow_serialise_doc	},
	{NULL,		NULL}		/* sentinel */
};


static PyMemberDef Flow_members[] = {
	{"data",	T_OBJECT, offsetof(FlowObject, user_attr),	0},
	{"src_addr",	T_STRING, offsetof(FlowObject, src_addr),	0},
	{"dst_addr",	T_STRING, offsetof(FlowObject, dst_addr),	0},
	{"agent_addr",	T_STRING, offsetof(FlowObject, agent_addr),	0},
	{"gateway_addr",T_STRING, offsetof(FlowObject, gateway_addr),	0},
	{"octets",	T_OBJECT, offsetof(FlowObject, octets),		0},
	{"packets",	T_OBJECT, offsetof(FlowObject, packets),	0},
	{"flow_ver",    FL_T_U8,  offsetof(FlowObject, flow.hdr.version),	0},
	{"fields",	FL_T_U32, offsetof(FlowObject, flow.hdr.fields),	0},
	{"tag",		FL_T_U32, offsetof(FlowObject, flow.tag.tag),	0},
	{"recv_sec",	FL_T_U32, offsetof(FlowObject, flow.recv_time.recv_sec),0},
	{"recv_usec",	FL_T_U32, offsetof(FlowObject, flow.recv_time.recv_usec),0},
	{"tcp_flags",	FL_T_U8,  offsetof(FlowObject, flow.pft.tcp_flags),	0},
	{"protocol",	FL_T_U8,  offsetof(FlowObject, flow.pft.protocol),	0},
	{"tos",		FL_T_U8,  offsetof(FlowObject, flow.pft.tos),	0},
	{"src_port",	FL_T_U16, offsetof(FlowObject, flow.ports.src_port),	0},
	{"dst_port",	FL_T_U16, offsetof(FlowObject, flow.ports.dst_port),	0},
	{"if_ndx_in",	FL_T_U32, offsetof(FlowObject, flow.ifndx.if_index_in),0},
	{"if_ndx_out",	FL_T_U32, offsetof(FlowObject, flow.ifndx.if_index_out),0},
	{"sys_uptime_ms",FL_T_U32,offsetof(FlowObject, flow.ainfo.sys_uptime_ms),0},
	{"agent_sec",	FL_T_U32, offsetof(FlowObject, flow.ainfo.time_sec),	0},
	{"agent_usec",	FL_T_U32, offsetof(FlowObject, flow.ainfo.time_nanosec),0},
	{"netflow_ver", FL_T_U16, offsetof(FlowObject, flow.ainfo.netflow_version),0},
	{"flow_start",	FL_T_U32, offsetof(FlowObject, flow.ftimes.flow_start),0},
	{"flow_finish",	FL_T_U32, offsetof(FlowObject, flow.ftimes.flow_finish),0},
	{"src_as",	FL_T_U32, offsetof(FlowObject, flow.asinf.src_as),	0},
	{"dst_as",	FL_T_U32, offsetof(FlowObject, flow.asinf.dst_as),	0},
	{"src_mask",	FL_T_U8,  offsetof(FlowObject, flow.asinf.src_mask),	0},
	{"dst_mask",	FL_T_U8,  offsetof(FlowObject, flow.asinf.dst_mask),	0},
	{"engine_type",	FL_T_U16, offsetof(FlowObject, flow.finf.engine_type),0},
	{"engine_id",	FL_T_U16, offsetof(FlowObject, flow.finf.engine_id),	0},
	{"flow_sequence",FL_T_U32,offsetof(FlowObject, flow.finf.flow_sequence),0},
	{"source_id",	FL_T_U32, offsetof(FlowObject, flow.finf.source_id),	0},
	{"crc32",	FL_T_U32, offsetof(FlowObject, flow.crc32.crc32),	0},
	{NULL}
};

PyDoc_STRVAR(Flow_doc, 
"Object representing a single NetFlow flow");

static PyTypeObject Flow_Type = {
	/* The ob_type field must be initialized in the module init function
	 * to be portable to Windows without using C++. */
	PyObject_HEAD_INIT(NULL)
	0,			/*ob_size*/
	"flowd.Flow",		/*tp_name*/
	sizeof(FlowObject),	/*tp_basicsize*/
	0,			/*tp_itemsize*/
	/* methods */
	(destructor)Flow_dealloc,/*tp_dealloc*/
	0,			/*tp_print*/
	0,			/*tp_getattr*/
	0,			/*tp_setattr*/
	0,			/*tp_compare*/
	0,			/*tp_repr*/
	0,			/*tp_as_number*/
	0,			/*tp_as_sequence*/
	0,			/*tp_as_mapping*/
	0,			/*tp_hash*/
	0,			/*tp_call*/
	0,			/*tp_str*/
	0,			/*tp_getattro*/
	0,			/*tp_setattro*/
	0,			/*tp_as_buffer*/
	Py_TPFLAGS_DEFAULT,	/*tp_flags*/
	Flow_doc,		/*tp_doc*/
	0,			/*tp_traverse*/
	0,			/*tp_clear*/
	0,			/*tp_richcompare*/
	0,			/*tp_weaklistoffset*/
	0,			/*tp_iter*/
	0,			/*tp_iternext*/
	Flow_methods,		/*tp_methods*/
	Flow_members,		/*tp_members*/
	0,			/*tp_getset*/
	0,			/*tp_base*/
	0,			/*tp_dict*/
	0,			/*tp_descr_get*/
	0,			/*tp_descr_set*/
	0,			/*tp_dictoffset*/
	0,			/*tp_init*/
	0,			/*tp_alloc*/
	0,			/*tp_new*/
	0,			/*tp_free*/
	0,			/*tp_is_gc*/
};

/* ------------------------------------------------------------------------ */

typedef struct _FlowLogObject {
	PyObject_HEAD
	PyObject *flowlog; /* PyFile */
} FlowLogObject;

static PyTypeObject FlowLog_Type;

/* FlowLog methods */

static void
FlowLog_dealloc(FlowLogObject *self)
{
	Py_XDECREF(self->flowlog);
	PyObject_Del(self);
}

PyDoc_STRVAR(FlowLog_read_flow_doc,
"FlowLog.read_flow() -> new Flow object\n\
\n\
Reads a flow record from the flow log and returns a Flow object\n\
");

static PyObject *
FlowLog_read_flow(FlowLogObject *self)
{
	struct store_flow_complete flow;
	char ebuf[512];

	switch (store_read_flow(PyFile_AsFile(self->flowlog), &flow, 
	    ebuf, sizeof(ebuf))) {
	case STORE_ERR_OK:
		return (PyObject *)newFlowObject_from_flow(&flow);
	case STORE_ERR_EOF:
		Py_INCREF(Py_None);
		return Py_None;
	default:
		PyErr_SetString(PyExc_ValueError, ebuf);
		return (NULL);
	}
	/* NOTREACHED */
}

PyDoc_STRVAR(FlowLog_write_flow_doc,
"FlowLog.write_flow(flow, mask = flowd.DISPLAY_ALL) -> None\n\
\n\
Writes a flow record to the flow log\n\
");

static PyObject *
FlowLog_write_flow(FlowLogObject *self, PyObject *args, PyObject *kw_args)
{
	struct store_flow_complete flow;
	static char *keywords[] = { "flow", "fieldmask", NULL };
	char ebuf[512];

	FlowObject *flowobj = NULL;
	u_int32_t mask = STORE_DISPLAY_ALL;

	if (!PyArg_ParseTupleAndKeywords(args, kw_args, "O!|k:write_flow",
	    keywords, &Flow_Type, (PyObject *)&flowobj, &mask))
		return NULL;

	if (flowobj_normalise(flowobj) == -1)
		return (NULL);

	memcpy(&flow, &flowobj->flow, sizeof(flow));
	store_swab_flow(&flow, 1);

	if (store_write_flow(PyFile_AsFile(self->flowlog), &flow, mask,
	    ebuf, sizeof(ebuf)) != STORE_ERR_OK) {
		PyErr_SetString(PyExc_ValueError, ebuf);
		return (NULL);
	}

	Py_INCREF(Py_None);
	return Py_None;
}

static PyObject *
FlowLog_getiter(FlowLogObject *self)
{
	return (PyObject *)newFlowLogIterObject(self);
}

static PyMemberDef FlowLog_members[] = {
	{"file",	T_OBJECT, offsetof(FlowLogObject, flowlog),	0},
	{NULL}
};

PyDoc_STRVAR(FlowLog_doc, "NetFlow log");

static PyMethodDef FlowLog_methods[] = {
	{"read_flow",	(PyCFunction)FlowLog_read_flow,	0,				FlowLog_read_flow_doc	},
	{"write_flow",	(PyCFunction)FlowLog_write_flow,METH_VARARGS|METH_KEYWORDS,	FlowLog_write_flow_doc	},
	{NULL,		NULL}		/* sentinel */
};

static PyTypeObject FlowLog_Type = {
	/* The ob_type field must be initialized in the module init function
	 * to be portable to Windows without using C++. */
	PyObject_HEAD_INIT(NULL)
	0,			/*ob_size*/
	"flowd.FlowLog",	/*tp_name*/
	sizeof(FlowLogObject),	/*tp_basicsize*/
	0,			/*tp_itemsize*/
	/* methods */
	(destructor)FlowLog_dealloc, /*tp_dealloc*/
	0,			/*tp_print*/
	0,			/*tp_getattr*/
	0,			/*tp_setattr*/
	0,			/*tp_compare*/
	0,			/*tp_repr*/
	0,			/*tp_as_number*/
	0,			/*tp_as_sequence*/
	0,			/*tp_as_mapping*/
	0,			/*tp_hash*/
	0,			/*tp_call*/
	0,			/*tp_str*/
	0,			/*tp_getattro*/
	0,			/*tp_setattro*/
	0,			/*tp_as_buffer*/
	Py_TPFLAGS_DEFAULT,	/*tp_flags*/
	FlowLog_doc,		/*tp_doc*/
	0,			/*tp_traverse*/
	0,			/*tp_clear*/
	0,			/*tp_richcompare*/
	0,			/*tp_weaklistoffset*/
	(getiterfunc)FlowLog_getiter, /*tp_iter*/
	0,			/*tp_iternext*/
	FlowLog_methods,	/*tp_methods*/
	FlowLog_members,	/*tp_members*/
	0,			/*tp_getset*/
	0,			/*tp_base*/
	0,			/*tp_dict*/
	0,			/*tp_descr_get*/
	0,			/*tp_descr_set*/
	0,			/*tp_dictoffset*/
	0,			/*tp_init*/
	0,			/*tp_alloc*/
	0,			/*tp_new*/
	0,			/*tp_free*/
	0,			/*tp_is_gc*/
};

/* ------------------------------------------------------------------------ */

/* FlowLogIter: netflow log iterator */

typedef struct _FlowLogIterObject {
	PyObject_HEAD
	FlowLogObject *parent;
} FlowLogIterObject;

static PyTypeObject FlowLogIter_Type;

static FlowLogIterObject *
newFlowLogIterObject(FlowLogObject *parent)
{
	FlowLogIterObject *self;

	self = PyObject_New(FlowLogIterObject, &FlowLogIter_Type);
	if (self == NULL)
		return NULL;

	self->parent = parent;
	Py_XINCREF(self->parent);

	return self;
}

/* FlowLogIter methods */

static void
FlowLogIter_dealloc(FlowLogIterObject *self)
{
	Py_XDECREF(self->parent);
	PyObject_Del(self);
}

static PyObject *
FlowLogIter_iternext(FlowLogIterObject *self)
{
	struct store_flow_complete flow;
	char ebuf[512];

	switch (store_read_flow(PyFile_AsFile(self->parent->flowlog), &flow, 
	    ebuf, sizeof(ebuf))) {
	case STORE_ERR_OK:
		return (PyObject *)newFlowObject_from_flow(&flow);
	case STORE_ERR_EOF:
		return NULL;
	default:
		PyErr_SetString(PyExc_ValueError, ebuf);
		return (NULL);
	}
	/* NOTREACHED */
}

PyDoc_STRVAR(FlowLogIter_doc, 
"FlowLog tree iterator");

static PyTypeObject FlowLogIter_Type = {
	/* The ob_type field must be initialized in the module init function
	 * to be portable to Windows without using C++. */
	PyObject_HEAD_INIT(NULL)
	0,			/*ob_size*/
	"flowd.FlowLogIter",	/*tp_name*/
	sizeof(FlowLogIterObject),/*tp_basicsize*/
	0,			/*tp_itemsize*/
	/* methods */
	(destructor)FlowLogIter_dealloc, /*tp_dealloc*/
	0,			/*tp_print*/
	0,			/*tp_getattr*/
	0,			/*tp_setattr*/
	0,			/*tp_compare*/
	0,			/*tp_repr*/
	0,			/*tp_as_number*/
	0,			/*tp_as_sequence*/
	0,			/*tp_as_mapping*/
	0,			/*tp_hash*/
	0,			/*tp_call*/
	0,			/*tp_str*/
	0,			/*tp_getattro*/
	0,			/*tp_setattro*/
	0,			/*tp_as_buffer*/
	Py_TPFLAGS_DEFAULT,	/*tp_flags*/
	FlowLogIter_doc,	/*tp_doc*/
	0,			/*tp_traverse*/
	0,			/*tp_clear*/
	0,			/*tp_richcompare*/
	0,			/*tp_weaklistoffset*/
	0,			/*tp_iter*/
	(iternextfunc)FlowLogIter_iternext, /*tp_iternext*/
	0,			/*tp_methods*/
	0,			/*tp_members*/
	0,			/*tp_getset*/
	0,			/*tp_base*/
	0,			/*tp_dict*/
	0,			/*tp_descr_get*/
	0,			/*tp_descr_set*/
	0,			/*tp_dictoffset*/
	0,			/*tp_init*/
	0,			/*tp_alloc*/
	0,			/*tp_new*/
	0,			/*tp_free*/
	0,			/*tp_is_gc*/
};

/* ------------------------------------------------------------------------ */

PyDoc_STRVAR(flow_Flow_doc,
"Flow(blob = None) -> new Flow object\n\
\n\
Instantiate a new Flow object. If the 'blob' parameter is specified,\n\
the flow will be created from the specified binary flow record, otherwise \n\
the Flow object will be created empty.");

static PyObject *
flow_Flow(PyObject *args, PyObject *kw_args)
{
	FlowObject *rv;
	static char *keywords[] = { "blob", NULL };
	char *blob = NULL;
	int bloblen = -1;

	if (!PyArg_ParseTupleAndKeywords(args, kw_args, "|s#:Flow", keywords,
	    &blob, &bloblen))
		return NULL;
	if (bloblen == -1)
		rv = newFlowObject();
	else
		rv = newFlowObject_from_blob(blob, bloblen);
	if (rv == NULL)
		return NULL;
	return (PyObject *)rv;
}

PyDoc_STRVAR(flow_FlowLog_doc,
"FlowLog(path, mode = \"rb\") -> new FlowFlow object\n\
\n\
Instantiate a new FlowLog object.\n\
");

static PyObject *
flow_FlowLog(PyObject *self, PyObject *args, PyObject *kw_args)
{
	FlowLogObject *rv;
	static char *keywords[] = { "path", "mode", NULL };
	char *path = NULL, *mode = "rb";

	if (!PyArg_ParseTupleAndKeywords(args, kw_args, "s|s:FlowLog", keywords,
	    &path, &mode))
		return NULL;
	if ((rv = PyObject_New(FlowLogObject, &FlowLog_Type)) == NULL)
		return (NULL);
	if ((rv->flowlog = PyFile_FromString(path, mode)) == NULL)
		return (NULL);
	PyFile_SetBufSize(rv->flowlog, 8192);

	return (PyObject *)rv;
}

static PyMethodDef flowd_methods[] = {
	{"Flow",	(PyCFunction)flow_Flow,    METH_VARARGS|METH_KEYWORDS,	flow_Flow_doc	},
	{"FlowLog",	(PyCFunction)flow_FlowLog, METH_VARARGS|METH_KEYWORDS,	flow_FlowLog_doc },
	{NULL,		NULL}		/* sentinel */
};

PyDoc_STRVAR(module_doc,
"Interface to flowd NetFlow log files.\n\
");

PyMODINIT_FUNC
initflowd(void)
{
	PyObject *m;

	if (PyType_Ready(&Flow_Type) < 0)
		return;
	if (PyType_Ready(&FlowLog_Type) < 0)
		return;
	m = Py_InitModule3("flowd", flowd_methods, module_doc);

#define STORE_CONST(c) \
	PyModule_AddObject(m, #c, PyLong_FromUnsignedLong(STORE_##c))
	STORE_CONST(FIELD_TAG);
	STORE_CONST(FIELD_RECV_TIME);
	STORE_CONST(FIELD_PROTO_FLAGS_TOS);
	STORE_CONST(FIELD_AGENT_ADDR4);
	STORE_CONST(FIELD_AGENT_ADDR6);
	STORE_CONST(FIELD_SRC_ADDR4);
	STORE_CONST(FIELD_SRC_ADDR6);
	STORE_CONST(FIELD_DST_ADDR4);
	STORE_CONST(FIELD_DST_ADDR6);
	STORE_CONST(FIELD_GATEWAY_ADDR4);
	STORE_CONST(FIELD_GATEWAY_ADDR6);
	STORE_CONST(FIELD_SRCDST_PORT);
	STORE_CONST(FIELD_PACKETS);
	STORE_CONST(FIELD_OCTETS);
	STORE_CONST(FIELD_IF_INDICES);
	STORE_CONST(FIELD_AGENT_INFO);
	STORE_CONST(FIELD_FLOW_TIMES);
	STORE_CONST(FIELD_AS_INFO);
	STORE_CONST(FIELD_FLOW_ENGINE_INFO);
	STORE_CONST(FIELD_CRC32);
	STORE_CONST(FIELD_RESERVED);
	STORE_CONST(FIELD_ALL);
	STORE_CONST(FIELD_AGENT_ADDR);
	STORE_CONST(FIELD_SRC_ADDR);
	STORE_CONST(FIELD_DST_ADDR);
	STORE_CONST(FIELD_SRCDST_ADDR);
	STORE_CONST(FIELD_GATEWAY_ADDR);
	STORE_CONST(DISPLAY_ALL);
	STORE_CONST(DISPLAY_BRIEF);
#undef STORE_CONST
#define STORE_CONST(c) \
	PyModule_AddObject(m, "STORE_"#c, PyLong_FromUnsignedLong(STORE_##c))
	STORE_CONST(VER_MAJOR);
	STORE_CONST(VER_MINOR);
	STORE_CONST(VERSION);
#undef STORE_CONST

	PyModule_AddStringConstant(m, "__version__", PROGVER);
}
