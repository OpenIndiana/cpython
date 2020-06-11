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
 * privileges(5) bindings for Python
 */

#include <priv.h>
#include "Python.h"

static PyObject *
pyprivileges_setppriv( PyObject *self, PyObject *args) {
	priv_op_t op = -1 ; 
	priv_ptype_t which = NULL;

	PyObject* set_list = NULL;

	priv_set_t * set = NULL;

	if(!PyArg_ParseTuple(args, "iiO:setppriv", &op, &which, &set_list))
		return NULL;
	
	if((op != PRIV_ON && op != PRIV_OFF && op != PRIV_SET) ||
		(which != PRIV_PERMITTED && which != PRIV_EFFECTIVE &&
		which != PRIV_INHERITABLE && which != PRIV_LIMIT))
		return NULL;
	
	PyObject* set_string = PyList_GetItem(set_list, 0);
	int i;
	for (i = 1; i < PyList_Size(set_list); ++i) {
		PyBytes_Concat(&set_string, PyBytes_FromString(","));
		PyBytes_Concat(&set_string, PyList_GetItem(set_list, i));
	}

	set = priv_str_to_set(PyBytes_AsString(set_string), ",", NULL );

	if ( set == NULL )
		return NULL;

	long ret = (long) setppriv(op, which, set);
	priv_freeset(set);	
	// Python inverts true & false
	if(ret)
		Py_RETURN_FALSE;
	
	Py_RETURN_TRUE;
}

static PyObject *
pyprivileges_getppriv( PyObject *self, PyObject *args) {

	char* set_str = NULL;
	priv_ptype_t which = NULL;
	priv_set_t * set = priv_allocset();
	if (set == NULL)
		return NULL;

	if(!PyArg_ParseTuple(args, "i:getppriv", &which))
		return NULL;

	if (which != PRIV_PERMITTED && which != PRIV_EFFECTIVE &&
	which != PRIV_INHERITABLE && which != PRIV_LIMIT)
		return NULL;

	if (getppriv(which, set) != 0)
		return NULL;
	
	set_str = priv_set_to_str(set, ',', PRIV_STR_LIT);
	priv_freeset(set);
	
	PyObject* set_list = PyList_New(NULL);
	char* saveptr;
	char* item = strtok_r(set_str, ",", &saveptr);
	PyList_Append(set_list, PyBytes_FromString(item));

	while((item = strtok_r(NULL, ",", &saveptr)) != NULL) {
		if(PyList_Append(set_list, PyBytes_FromString(item)) != 0) {
			Py_XDECREF(set_list);
			return NULL;
		}
	}

	return(set_list);
}

static PyObject *
pyprivileges_priv_inverse( PyObject *self, PyObject *args ) {

	PyObject* set_list_in = NULL;
	if(!PyArg_ParseTuple(args, "O:priv_inverse", &set_list_in))
		return NULL;

	PyObject* set_string = PyList_GetItem(set_list_in, 0);
	int i;
	for (i = 1; i < PyList_Size(set_list_in); ++i) {
		PyBytes_Concat(set_string, PyBytes_FromString(","));
		PyBytes_Concat(set_string, PyList_GetItem(set_list_in, i));
	}

	priv_set_t * set = priv_str_to_set(PyBytes_AsString(set_string), ",", NULL);
	if (set == NULL)
		return NULL;
	priv_inverse(set);
	char * ret_str = priv_set_to_str(set, ',', PRIV_STR_LIT);
	priv_freeset(set);
	
	PyObject* set_list_out = PyList_New(NULL);
	char* saveptr;
	char* item = strtok_r(ret_str, ",", &saveptr);
	PyList_Append(set_list_out, PyBytes_FromString(item));

	while((item = strtok_r(NULL, ",", &saveptr)) != NULL) {
		if(PyList_Append(set_list_out, PyBytes_FromString(item)) != 0) {
			Py_XDECREF(set_list_out);
			return NULL;
		}
	}
	
	Py_XDECREF(set_list_in);
	
	return(set_list_out);
}

/* priv_ineffect is a convienient wrapper to priv_get
 * however priv_set is, in the context of python, not
 * much of a convienience, so it's omitted
 */
static PyObject * 
pyprivileges_priv_ineffect(PyObject* self, PyObject* args) {
	char* privstring=NULL;
	if (!PyArg_ParseTuple(args, "s:priv_ineffect", &privstring))
		return NULL;
	return PyBool_FromLong(priv_ineffect(privstring));
}


static char pyprivileges__doc__[];
PyDoc_STRVAR(pyprivileges__doc__, 
"Provides functions for interacting with the Solaris privileges(5) framework\n\
Functions provided:\n\
setppriv\n\
getppriv\n\
priv_ineffect\n\
priv_inverse");

static char pyprivileges_setppriv__doc__[];
static char pyprivileges_getppriv__doc__[];
static char pyprivileges_priv_ineffect__doc__[];
static char pyprivileges_priv_inverse__doc__[];

PyDoc_STRVAR(pyprivileges_setppriv__doc__, 
"Facilitates setting the permitted/inheritable/limit/effective privileges set\n\
\tArguments:\n\
\t\tone of (PRIV_ON|PRIV_OFF|PRIV_SET)\n\
\t\tone of (PRIV_PERMITTED|PRIV_INHERITABLE|PRIV_LIMIT|PRIV_EFFECTIVE)\n\
\t\tset of privileges: a list of strings\n\
\tReturns: True on success, False on failure\
");

PyDoc_STRVAR(pyprivileges_getppriv__doc__, 
"Return the process privilege set\n\
\tArguments:\n\
\t\tone of (PRIV_PERMITTED|PRIV_INHERITABLE|PRIV_LIMIT|PRIV_EFFECTIVE)\n\
\tReturns: a Python list of strings");
	
PyDoc_STRVAR(pyprivileges_priv_ineffect__doc__, 
"Checks for a privileges presence in the effective set\n\
\tArguments: a String\n\
\tReturns: True if the privilege is in effect, False otherwise");

PyDoc_STRVAR(pyprivileges_priv_inverse__doc__, 
"The complement of the set of privileges\n\
\tArguments: a list of strings\n\tReturns: a list of strings");

static PyMethodDef module_methods[] = {
	{"setppriv", pyprivileges_setppriv, METH_VARARGS, pyprivileges_setppriv__doc__}, 
	{"getppriv", pyprivileges_getppriv, METH_VARARGS, pyprivileges_getppriv__doc__}, 
	{"priv_ineffect", pyprivileges_priv_ineffect, METH_VARARGS, pyprivileges_priv_ineffect__doc__},
	{"priv_inverse", pyprivileges_priv_inverse, METH_VARARGS, pyprivileges_priv_inverse__doc__},
	{NULL, NULL}
};


#ifndef PyMODINIT_FUNC	/* declarations for DLL import/export */
#define PyMODINIT_FUNC void
#endif
PyMODINIT_FUNC
PyInit_privileges (void) {
	PyObject* m;

	static struct PyModuleDef moduledef = {
	    PyModuleDef_HEAD_INIT,
	    "privileges",
	    pyprivileges__doc__,
	    -1,
	    module_methods,
	    NULL,
	    NULL,
	    NULL,
	    NULL,
	};

	m = PyModule_Create(&moduledef);
	if ( m == NULL )
		return m;
		
	PyObject* d = PyModule_GetDict(m);
	if (d == NULL)
		return m;

	PyDict_SetItemString(d, "PRIV_ON", PyLong_FromLong((long)PRIV_ON));
	PyDict_SetItemString(d, "PRIV_OFF", PyLong_FromLong((long)PRIV_OFF));
	PyDict_SetItemString(d, "PRIV_SET", PyLong_FromLong((long)PRIV_SET));

	PyDict_SetItemString(d, "PRIV_PERMITTED", PyLong_FromLong((long)PRIV_PERMITTED));
	PyDict_SetItemString(d, "PRIV_INHERITABLE", PyLong_FromLong((long)PRIV_INHERITABLE));
	PyDict_SetItemString(d, "PRIV_LIMIT", PyLong_FromLong((long)PRIV_LIMIT));
	PyDict_SetItemString(d, "PRIV_EFFECTIVE", PyLong_FromLong((long)PRIV_EFFECTIVE));

       return m;
}
