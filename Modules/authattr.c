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
 * RBAC Bindings for Python - auth_attr functions
 */

#include <auth_attr.h>
#include "Python.h"
#include "pyrbac.h"

static PyObject*
pyrbac_setauthattr(PyObject* self, PyObject* args) {
	setauthattr();
	return Py_None;
}

static PyObject*
pyrbac_endauthattr(PyObject* self, PyObject* args) {
	endauthattr();
	return Py_None;
}

PyObject*
pyrbac_getauthnamattr(PyObject* self, char* authname, int mode) {
	

	
	authattr_t * ret_authattr = (mode == PYRBAC_NAM_MODE) ? getauthnam(authname) : getauthattr();
	if (ret_authattr == NULL)
		return Py_None;
		
	PyObject* kv_data = PyDict_New();
	if (kv_data == NULL) {
		free_authattr(ret_authattr);
		return NULL;
	}

	if(ret_authattr->attr != NULL) {
		int len;
		for(len = 0; len < ret_authattr->attr->length; len++) {
			kv_t current = ret_authattr->attr->data[len];

			PyObject* set = PyList_New(NULL);
			char* saveptr;
			char* item = strtok_r(current.value, ",", &saveptr);
			PyList_Append(set, PyBytes_FromString(item));

			while((item = strtok_r(NULL, ",", &saveptr)) != NULL) {
				if(PyList_Append(set, PyBytes_FromString(item)) != 0) {
					Py_XDECREF(set);
					Py_XDECREF(kv_data);
					free_authattr(ret_authattr);
					return NULL;
				}
			}
			if(PyDict_SetItemString(kv_data, current.key, set)) {
					free_authattr(ret_authattr);
					return NULL;
			}
		}
	}
	PyObject * retval = Py_BuildValue("{s:s,s:s,s:s,s:s,s:s,s:O}",
		"name",ret_authattr->name,
		"res1",ret_authattr->res1,
		"res2",ret_authattr->res2,
		"short",ret_authattr->short_desc,
		"long",ret_authattr->long_desc,
		"attributes",kv_data);

	free_authattr(ret_authattr);
	return retval;

}

static PyObject*
pyrbac_getauthattr(PyObject* self, PyObject* args) {
	return(pyrbac_getauthnamattr(self, NULL, PYRBAC_ATTR_MODE));
}

static PyObject*
pyrbac_getauthnam(PyObject* self, PyObject* args) {
	char* name = NULL;
	if(!PyArg_ParseTuple(args, "s:getauthnam", &name))
		return NULL;
	return(pyrbac_getauthnamattr(self, name, PYRBAC_NAM_MODE));
}

static PyObject *
pyrbac_chkauthattr(PyObject* self, PyObject* args) {
	char* authstring = NULL;
	char* username = NULL;
	if(!PyArg_ParseTuple(args, "ss:chkauthattr", &authstring, &username))
		return NULL;
	return PyBool_FromLong((long)chkauthattr(authstring, username));
}

static PyObject*
pyrbac_authattr_next(PyObject* self, PyObject* args) {
	PyObject* retval = pyrbac_getauthattr(self, args);
	if( retval == Py_None ) {
		setauthattr();
		return NULL;
	}
	return retval;
}
static PyObject*
pyrbac_authattr__iter__(PyObject* self, PyObject* args) {
	return self;
}

typedef struct {
	PyObject_HEAD
} Authattr;

static void
Authattr_dealloc(Authattr* self) {
	endauthattr();
	Py_TYPE(self)->tp_free((PyObject*) self);
}

static PyObject*
Authattr_new(PyTypeObject *type, PyObject *args, PyObject *kwds) {
	Authattr *self;
	self = (Authattr*)type->tp_alloc(type, 0);

	return ((PyObject *) self);
}

static int
Authattr_init(Authattr* self, PyObject *args, PyObject *kwargs) {
	setauthattr();
	return 0;
}

static char pyrbac_authattr__doc__[];

PyDoc_STRVAR(pyrbac_authattr__doc__, """provides interfaces to the auth_attr \
database. may be iterated over to return all auth_attr entries\n\n\
Methods provided:\n\
setauthattr\n\
endauthattr\n\
getauthattr\n\
chkauthattr\n\
getauthnam""");

static char pyrbac_setauthattr__doc__[];
static char pyrbac_endauthattr__doc__[];
static char pyrbac_getauthattr__doc__[];
static char pyrbac_chkauthattr__doc__[];

PyDoc_STRVAR(pyrbac_setauthattr__doc__, 
"\"rewinds\" the auth_attr functions to the first entry in the db. Called \
automatically by the constructor\n\tArguments: None\n\tReturns: None");

PyDoc_STRVAR(pyrbac_endauthattr__doc__, 
"closes the auth_attr database, cleans up storage. called automatically by \
the destructor\n\tArguments: None\n\tReturns: None");

PyDoc_STRVAR(pyrbac_chkauthattr__doc__, "verifies if a user has a given \
authorization.\n\tArguments: 2 Python strings, 'authname' and 'username'\n\
\tReturns: True if the user is authorized, False otherwise");

PyDoc_STRVAR(pyrbac_getauthattr__doc__, 
"return one entry from the auth_attr database\n\
\tArguments: None\n\
\tReturns: a dict representing the authattr_t struct:\n\
\t\t\"name\": Authorization Name\n\
\t\t\"res1\": reserved\n\
\t\t\"res2\": reserved\n\
\t\t\"short\": Short Description\n\
\t\t\"long\": Long Description\n\
\t\t\"attributes\": A Python dict keyed by attribute & valued as either a list \
or a string depending on value");

PyDoc_STRVAR(pyrbac_getauthnam__doc__, 
"searches the auth_attr database for a given authorization name\n\
\tArguments: a Python string containing the auth name\n\
\tReturns: a dict representing the authattr_t struct:\n\
\t\t\"name\": Authorization Name\n\
\t\t\"res1\": reserved\n\
\t\t\"res2\": reserved\n\
\t\t\"short\": Short Description\n\
\t\t\"long\": Long Description\n\
\t\t\"attributes\": A Python dict keyed by attribute & valued as either a list \
or a string depending on value");

static PyMethodDef Authattr_methods[] = {
	{"setauthattr", pyrbac_setauthattr, METH_NOARGS, pyrbac_setauthattr__doc__},
	{"endauthattr", pyrbac_endauthattr, METH_NOARGS, pyrbac_endauthattr__doc__},
	{"chkauthattr", pyrbac_chkauthattr, METH_VARARGS, pyrbac_chkauthattr__doc__},
	{"getauthattr", pyrbac_getauthattr, METH_NOARGS, pyrbac_getauthattr__doc__},
	{"getauthnam", pyrbac_getauthnam, METH_VARARGS, pyrbac_getauthnam__doc__},
	{NULL, NULL}
};

PyTypeObject AuthattrType = {
	PyVarObject_HEAD_INIT(NULL, 0)
	"rbac.authattr",              /*tp_name*/
	sizeof(Authattr),             /*tp_basicsize*/
	0,                            /*tp_itemsize*/
	(destructor)Authattr_dealloc, /*tp_dealloc*/
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
	pyrbac_authattr__doc__,       /* tp_doc */
	0,		              /* tp_traverse */
	0,		              /* tp_clear */
	0,		              /* tp_richcompare */
	0,		              /* tp_weaklistoffset */
	pyrbac_authattr__iter__,      /* tp_iter */
	pyrbac_authattr_next,         /* tp_iternext */
	Authattr_methods,             /* tp_methods */
	0,                            /* tp_members */
	0,                            /* tp_getset */
	0,                            /* tp_base */
	0,                            /* tp_dict */
	0,                            /* tp_descr_get */
	0,                            /* tp_descr_set */
	0,                            /* tp_dictoffset */
	(initproc)Authattr_init,      /* tp_init */
	0,                            /* tp_alloc */
	Authattr_new,                 /* tp_new */
	0,                            /* tp_free */
	0,                            /* tp_is_gc */
};
