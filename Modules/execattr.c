/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */

/*
 * Copyright (c) 2011, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * RBAC Bindings for Python - exec_attr functions
 */

#include <exec_attr.h>
#include "Python.h"
#include "pyrbac.h"

static PyObject *
pyrbac_setexecattr(PyObject* self, PyObject* args) {
	setexecattr();
	return Py_None;
}

static PyObject *
pyrbac_endexecattr(PyObject* self, PyObject* args) {
	endexecattr();
	return Py_None;
}

PyObject *
pyrbac_getexecuserprofattr(PyObject* self, char* userprofname, char* type, char* id, int mode) {

	PyObject* ep_data = (mode == PYRBAC_ATTR_MODE) ? NULL : PyList_New(0);
	
	if (ep_data == NULL && mode != PYRBAC_ATTR_MODE )
		return NULL;
	
	execattr_t *execprof;
	if (mode == PYRBAC_USER_MODE)
		execprof = getexecuser(userprofname, type, id, GET_ALL);
	else if (mode == PYRBAC_PROF_MODE)
		execprof = getexecprof(userprofname, type, id, GET_ALL);
	else if (mode == PYRBAC_ATTR_MODE)
		execprof = getexecattr();
	else
		return NULL;

	if (execprof == NULL)
		return Py_None;
	
	execattr_t *execprof_head = execprof;

	while(execprof != NULL) {
		
		PyObject* kv_data = PyDict_New();

		if(execprof->attr != NULL) {
			int len;
			for(len = 0; len < execprof->attr->length; len++) {
				kv_t current = execprof->attr->data[len];

				PyObject* set = PyList_New(NULL);
				char* saveptr;
				char* item = strtok_r(current.value, ",", &saveptr);
				PyList_Append(set, PyBytes_FromString(item));

				while((item = strtok_r(NULL, ",", &saveptr)) != NULL) {
					if(PyList_Append(set, PyBytes_FromString(item)) != 0) {
						Py_XDECREF(set);
						Py_XDECREF(kv_data);
						free_execattr(execprof_head);
						return NULL;
					}
				}
				if(PyDict_SetItemString(kv_data, current.key, set)) {
						free_execattr(execprof_head);
						return NULL;
				}
			}
		}
		PyObject* entry = Py_BuildValue("{s:s,s:s,s:s,s:s,s:s,s:s,s:O}",
			"name", execprof->name,
			"type", execprof->type,
			"policy", execprof->policy,
			"res1", execprof->res1,
			"res2", execprof->res2,
			"id", execprof->id,
			"attributes", kv_data);
		
		if (entry == NULL) {
			Py_XDECREF(kv_data);
			free_execattr(execprof_head);
			return NULL;
		}
		
		if (mode == PYRBAC_ATTR_MODE) {
			free_execattr(execprof_head);
			return(entry);
		}
		PyList_Append(ep_data, entry);
		execprof = execprof->next;
	}

	free_execattr(execprof_head);
	return(ep_data);
 
}

static PyObject *
pyrbac_getexecuser(PyObject* self, PyObject* args) {
	char* username = NULL;
	char* type = NULL;
	char* id = NULL;
	
	if(!PyArg_ParseTuple(args, "sss:getexecuser", &username, &type, &id))
		return NULL;

	return (pyrbac_getexecuserprofattr(self, username, type, id, PYRBAC_USER_MODE));
}

static PyObject *
pyrbac_getexecprof(PyObject* self, PyObject* args) {

	char* profname = NULL;
	char* type = NULL;
	char* id = NULL;
	
	if(!PyArg_ParseTuple(args, "sss:getexecprof", &profname, &type, &id))
		return NULL;

	return (pyrbac_getexecuserprofattr(self, profname, type, id, PYRBAC_PROF_MODE));
}

static PyObject*
pyrbac_getexecattr(PyObject* self, PyObject* args) {
	return pyrbac_getexecuserprofattr(self, NULL, NULL, NULL, PYRBAC_ATTR_MODE);
}

static PyObject*
pyrbac_execattr_next(PyObject* self, PyObject* args) {
	PyObject* retval = pyrbac_getexecattr(self, args);
	if( retval == Py_None ) {
		setexecattr();
		return NULL;
	}
	return retval;
}
static PyObject*
pyrbac_execattr__iter__(PyObject* self, PyObject* args) {
	return self;
}

typedef struct {
	PyObject_HEAD
} Execattr;

static void
Execattr_dealloc(Execattr* self) {
	endexecattr();
	Py_TYPE(self)->tp_free((PyObject*) self);
}

static PyObject*
Execattr_new(PyTypeObject *type, PyObject *args, PyObject *kwds) {
	Execattr *self;
	self = (Execattr*)type->tp_alloc(type, 0);

	return ((PyObject *) self);
}

static int
Execattr_init(Execattr* self, PyObject *args, PyObject *kwargs) {
	setexecattr();
	return 0;
}

static char pyrbac_execattr__doc__[];

PyDoc_STRVAR(pyrbac_execattr__doc__, "provides functions for \
interacting with the execution profiles database. May be iterated over to \
enumerate exec_attr(4) entries\n\n\
Methods provided:\n\
setexecattr\n\
endexecattr\n\
getexecattr\n\
getexecprof\n\
getexecuser");


static char pyrbac_getexecuser__doc__[];
static char pyrbac_getexecprof__doc__[];
static char pyrbac_getexecattr__doc__[];
static char pyrbac_setexecattr__doc__[];
static char pyrbac_endexecattr__doc__[];

PyDoc_STRVAR(pyrbac_setexecattr__doc__,
"\"rewinds\" the exec_attr functions to the first entry in the db. Called \
automatically by the constructor.\n\
\tArguments: None\
\tReturns: None");

PyDoc_STRVAR(pyrbac_endexecattr__doc__, 
"closes the exec_attr database, cleans up storage. called automatically by \
the destructor.\n\
\tArguments: None\
\tReturns: None");

PyDoc_STRVAR(pyrbac_getexecuser__doc__, "corresponds with getexecuser(3SECDB)\
\nTakes: \'username\', \'type\', \'id\'\n\
Return: a single exec_attr entry\n\
\tArguments: None\n\
\tReturns: a dict representation of an execattr_t struct:\n\
\t\t\"name\": Authorization Name\n\
\t\t\"type\": Profile Type\n\
\t\t\"policy\": Policy attributes are relevant in\n\
\t\t\"res1\": reserved\n\
\t\t\"res2\": reserved\n\
\t\t\"id\": unique identifier\n\
\t\t\"attributes\": A Python dict keyed by attribute & valued as\
either a list or a string depending on value");

PyDoc_STRVAR(pyrbac_getexecprof__doc__, "corresponds with getexecprof(3SECDB)\
\nTakes: \'profile name\', \'type\', \'id\'\n\
\tReturns: a dict representation of an execattr_t struct:\n\
\t\t\"name\": Authorization Name\n\
\t\t\"type\": Profile Type\n\
\t\t\"policy\": Policy attributes are relevant in\n\
\t\t\"res1\": reserved\n\
\t\t\"res2\": reserved\n\
\t\t\"id\": unique identifier\n\
\t\t\"attributes\": A Python dict keyed by attribute & valued as\
either a list or a string depending on value");

PyDoc_STRVAR(pyrbac_getexecattr__doc__, "corresponds with getexecattr(3SECDB)\
\nTakes 0 arguments\n\
\tReturns: a dict representation of an execattr_t struct:\n\
\t\t\"name\": Authorization Name\n\
\t\t\"type\": Profile Type\n\
\t\t\"policy\": Policy attributes are relevant in\n\
\t\t\"res1\": reserved\n\
\t\t\"res2\": reserved\n\
\t\t\"id\": unique identifier\n\
\t\t\"attributes\": A Python dict keyed by attribute & valued as\
either a list or a string depending on value");

static PyMethodDef Execattr_methods[] = {
	{"setexecattr", pyrbac_setexecattr, METH_NOARGS, pyrbac_setexecattr__doc__},
	{"endexecattr", pyrbac_endexecattr, METH_NOARGS, pyrbac_endexecattr__doc__},
	{"getexecprof", pyrbac_getexecprof, METH_VARARGS, pyrbac_getexecprof__doc__},	
	{"getexecuser", pyrbac_getexecuser, METH_VARARGS, pyrbac_getexecuser__doc__},
	{"getexecattr", pyrbac_getexecattr, METH_NOARGS, pyrbac_getexecattr__doc__},
	{NULL, NULL}
};

PyTypeObject ExecattrType = {
	PyVarObject_HEAD_INIT(NULL, 0)
	"rbac.execattr",              /*tp_name*/
	sizeof(Execattr),             /*tp_basicsize*/
	0,                            /*tp_itemsize*/
	(destructor)Execattr_dealloc, /*tp_dealloc*/
	0,                            /*tp_print*/
	0,                            /*tp_getattr*/
	0,                            /*tp_setattr*/
	0,                            /*tp_reserved*/
	0,                            /*tp_repr*/
	0,                            /*tp_as_number*/
	0,                            /*tp_as_sequence*/
	0,                            /*tp_as_mapping*/
	0,                            /*tp_hash */
	0,                            /*tp_call*/
	0,                            /*tp_str*/
	0,                            /*tp_getattro*/
	0,                            /*tp_setattro*/
	0,                            /*tp_as_buffer*/
	Py_TPFLAGS_DEFAULT |
	Py_TPFLAGS_BASETYPE,          /*tp_flags*/
	pyrbac_execattr__doc__,       /* tp_doc */
	0,		              /* tp_traverse */
	0,		              /* tp_clear */
	0,		              /* tp_richcompare */
	0,		              /* tp_weaklistoffset */
	pyrbac_execattr__iter__,      /* tp_iter */
	pyrbac_execattr_next,         /* tp_iternext */
	Execattr_methods,             /* tp_methods */
	0,                            /* tp_members */
	0,                            /* tp_getset */
	0,                            /* tp_base */
	0,                            /* tp_dict */
	0,                            /* tp_descr_get */
	0,                            /* tp_descr_set */
	0,                            /* tp_dictoffset */
	(initproc)Execattr_init,      /* tp_init */
	0,                            /* tp_alloc */
	Execattr_new,                 /* tp_new */
	0,                            /* tp_free */
	0,                            /* tp_is_gc */
};
