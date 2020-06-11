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
 * RBAC Bindings for Python - user_attr functions
 */

#include <stdio.h>
#include <user_attr.h>
#include "Python.h"
#include "pyrbac.h"

static PyObject*
pyrbac_setuserattr(PyObject* self, PyObject* args) {
	setuserattr();
	return Py_None;
}

static PyObject*
pyrbac_enduserattr(PyObject* self, PyObject* args) {
	enduserattr();
	return Py_None;
}

PyObject*
pyrbac_getuseruidnamattr(PyObject* self, void* arg, int mode, char* filename) {
	
	userattr_t *ret_userattr;

	if (mode == PYRBAC_ATTR_MODE) {
	    if (filename != NULL) {
            FILE* file = fopen(filename, "r");
            if (file == NULL)
                return NULL;
	        ret_userattr = fgetuserattr(file);
	        if (fclose(file))
                return NULL;
	    }
	    else
	    	ret_userattr = getuserattr();
	}
	else if (mode == PYRBAC_NAM_MODE)
		ret_userattr = getusernam((char*) arg);
	else if (mode == PYRBAC_UID_MODE)
		ret_userattr = getuseruid(*((uid_t*) arg));
	
	if (ret_userattr == NULL)
		return Py_None;
	
	PyObject* entry = PyTuple_New(5);
	if (entry == NULL) {
		free_userattr(ret_userattr);
		return NULL;
	}
	
	PyObject* kv_data = PyDict_New();

	if(ret_userattr->attr != NULL) {
		int len;
		for(len = 0; len < ret_userattr->attr->length; len++) {
			kv_t current = ret_userattr->attr->data[len];

			PyObject* set = PyList_New(NULL);
			char* saveptr;
			char* item = strtok_r(current.value, ",", &saveptr);
			PyList_Append(set, PyBytes_FromString(item));

			while((item = strtok_r(NULL, ",", &saveptr)) != NULL) {
				if(PyList_Append(set, PyBytes_FromString(item)) != 0) {
					Py_XDECREF(set);
					Py_XDECREF(kv_data);
					free_userattr(ret_userattr);
					return NULL;
				}
			}
			if(PyDict_SetItemString(kv_data, current.key, set)) {
					free_userattr(ret_userattr);
					return NULL;
			}
		}
	}
	entry = Py_BuildValue("{s:s,s:s,s:s,s:s,s:O}", 
		"name", ret_userattr->name,
		"qualifier", ret_userattr->qualifier,
		"res1", ret_userattr->res1,
		"res2", ret_userattr->res2,
		"attributes", kv_data);

	free_userattr(ret_userattr);
	
	return entry;
}


static PyObject*
pyrbac_getuserattr(PyObject* self, PyObject* args) {
	return(pyrbac_getuseruidnamattr(self, (void*) NULL, PYRBAC_ATTR_MODE, NULL));
}

static PyObject*
pyrbac_fgetuserattr(PyObject* self, PyObject* args) {
	char* filename = NULL;
	if(!PyArg_ParseTuple(args, "s:fgetuserattr", &filename))
		return NULL;
	return(pyrbac_getuseruidnamattr(self, NULL, PYRBAC_ATTR_MODE, filename));
}

static PyObject*
pyrbac_getusernam(PyObject* self, PyObject* args) {
	char* name = NULL;
	if(!PyArg_ParseTuple(args, "s:getusernam", &name))
		return NULL;
	return(pyrbac_getuseruidnamattr(self, (void*) name, PYRBAC_NAM_MODE, NULL));
}

static PyObject*
pyrbac_getuseruid(PyObject* self, PyObject* args) {
	uid_t uid;
	if(!PyArg_ParseTuple(args, "i:getuseruid", &uid))
		return NULL;
	return(pyrbac_getuseruidnamattr(self, (void*) &uid, PYRBAC_UID_MODE, NULL));
}

static PyObject*
pyrbac_userattr_next(PyObject* self, PyObject* args) {
	PyObject* retval = pyrbac_getuserattr(self, args);
	if( retval == Py_None ) {
		setuserattr();
		return NULL;
	}
	return retval;
}
static PyObject*
pyrbac_userattr__iter__(PyObject* self, PyObject* args) {
	return self;
}

typedef struct {
	PyObject_HEAD
} Userattr;

static void
Userattr_dealloc(Userattr* self) {
	enduserattr();
	Py_TYPE(self)->tp_free((PyObject*) self);
}

static PyObject*
Userattr_new(PyTypeObject *type, PyObject *args, PyObject *kwds) {
	Userattr *self;
	self = (Userattr*)type->tp_alloc(type, 0);

	return ((PyObject *) self);
}

static int
Userattr_init(Userattr* self, PyObject *args, PyObject *kwargs) {
	setuserattr();
	return 0;
}

static char pyrbac_userattr__doc__[];
PyDoc_STRVAR(pyrbac_userattr__doc__, "provides functions for \
interacting with the extended user attributes database. May be iterated over \
to enumerate user_attr(4) entries\n\n\
Methods provided:\n\
setuserattr\n\
enduserattr\n\
getuserattr\n\
fgetuserattr\n\
getusernam\n\
getuseruid");

static char pyrbac_setuserattr__doc__[];
static char pyrbac_enduserattr__doc__[];
static char pyrbac_getuserattr__doc__[];
static char pyrbac_getusernam__doc__[];
static char pyrbac_getuseruid__doc__[];

PyDoc_STRVAR(pyrbac_setuserattr__doc__, "\"rewinds\" the user_attr functions \
to the first entry in the db. Called automatically by the constructor.\n\
\tArguments: None\n\
\tReturns: None");

PyDoc_STRVAR(pyrbac_enduserattr__doc__, "closes the user_attr database, \
cleans up storage. called automatically by the destructor\n\
\tArguments: None\n\
\tReturns: None");

PyDoc_STRVAR(pyrbac_getuserattr__doc__, "Return a single user_attr entry\n \
\tArguments: None\n\
\tReturns: a dict representation of a userattr_t struct:\n\
\t\t\"name\": username\n\
\t\t\"qualifier\": reserved\n\
\t\t\"res1\": reserved\n\
\t\t\"res2\": reserved\n\
\t\t\"attributes\": A Python dict keyed by attribute & valued as either a list \
or a string depending on value"
);

PyDoc_STRVAR(pyrbac_fgetuserattr__doc__, "Return a single user_attr entry \
from a file, bypassing nsswitch.conf\n\
\tArguments: \'filename\'\n\
\tReturns: a dict representation of a userattr_t struct:\n\
\t\t\"name\": username\n\
\t\t\"qualifier\": reserved\n\
\t\t\"res1\": reserved\n\
\t\t\"res2\": reserved\n\
\t\t\"attributes\": A Python dict keyed by attribute & valued as either a list \
or a string depending on value");

PyDoc_STRVAR(pyrbac_getusernam__doc__, "Searches for a user_attr entry with a \
given user name\n\
\tArgument: \'username\'\n\
\tReturns: a dict representation of a userattr_t struct:\n\
\t\t\"name\": username\n\
\t\t\"qualifier\": reserved\n\
\t\t\"res1\": reserved\n\
\t\t\"res2\": reserved\n\
\t\t\"attributes\": A Python dict keyed by attribute & valued as either a list \
or a string depending on value");

PyDoc_STRVAR(pyrbac_getuseruid__doc__, "Searches for a user_attr entry with a \
given uid\n\
\tArgument: uid\n\
\tReturns: a dict representation of a userattr_t struct:\n\
\t\t\"name\": username\n\
\t\t\"qualifier\": reserved\n\
\t\t\"res1\": reserved\n\
\t\t\"res2\": reserved\n\
\t\t\"attributes\": A Python dict keyed by attribute & valued as either a list \
or a string depending on value");

static PyMethodDef Userattr_methods[] = {
	{"setuserattr", pyrbac_setuserattr, METH_NOARGS, pyrbac_setuserattr__doc__},
	{"enduserattr", pyrbac_enduserattr, METH_NOARGS, pyrbac_enduserattr__doc__},
	{"getuserattr", pyrbac_getuserattr, METH_NOARGS, pyrbac_getuserattr__doc__},
	{"fgetuserattr", pyrbac_fgetuserattr, METH_VARARGS, pyrbac_fgetuserattr__doc__},
	{"getusernam", pyrbac_getusernam, METH_VARARGS, pyrbac_getusernam__doc__},
	{"getuseruid", pyrbac_getuseruid, METH_VARARGS, pyrbac_getuseruid__doc__},
	{NULL, NULL}
};

PyTypeObject UserattrType = {
	PyVarObject_HEAD_INIT(NULL, 0)
	"rbac.userattr",              /*tp_name*/
	sizeof(Userattr),             /*tp_basicsize*/
	0,                            /*tp_itemsize*/
	(destructor)Userattr_dealloc, /*tp_dealloc*/
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
	pyrbac_userattr__doc__,       /* tp_doc */
	0,		              /* tp_traverse */
	0,		              /* tp_clear */
	0,		              /* tp_richcompare */
	0,		              /* tp_weaklistoffset */
	pyrbac_userattr__iter__,      /* tp_iter */
	pyrbac_userattr_next,         /* tp_iternext */
	Userattr_methods,             /* tp_methods */
	0,                            /* tp_members */
	0,                            /* tp_getset */
	0,                            /* tp_base */
	0,                            /* tp_dict */
	0,                            /* tp_descr_get */
	0,                            /* tp_descr_set */
	0,                            /* tp_dictoffset */
	(initproc)Userattr_init,      /* tp_init */
	0,                            /* tp_alloc */
	Userattr_new,                 /* tp_new */
	0,                            /* tp_free */
	0,                            /* tp_is_gc */
};
