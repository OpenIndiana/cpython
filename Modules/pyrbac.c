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
 * RBAC Bindings for Python
 */

#include <Python.h>
#include "pyrbac.h"

static PyMethodDef module_methods[] = {NULL};
static char pyrbac__doc__[];

PyDoc_STRVAR(pyrbac__doc__, "provides access to some objects \
for interaction with the Solaris Role-Based Access Control \
framework.\n\nDynamic objects:\n\
userattr -- for interacting with user_attr(4)\n\
authattr -- for interacting with auth_attr(4)\n\
execattr -- for interacting with exec_attr(4)\n");

#ifndef PyMODINIT_FUNC	/* declarations for DLL import/export */
#define PyMODINIT_FUNC void
#endif
PyMODINIT_FUNC
PyInit_rbac (void) {
	PyObject* m;

	if (PyType_Ready(&AuthattrType) < 0 || 
		PyType_Ready(&ExecattrType) < 0 ||
		PyType_Ready(&UserattrType) < 0 )
		return NULL;

       static struct PyModuleDef moduledef = {
           PyModuleDef_HEAD_INIT,
           "rbac",
           pyrbac__doc__,
           -1,
           module_methods,
           NULL,
           NULL,
           NULL,
           NULL,
       };

       m = PyModule_Create(&moduledef);
	if ( m == NULL )
		return NULL;
	
	Py_INCREF(&AuthattrType);
	PyModule_AddObject(m, "authattr", (PyObject*)&AuthattrType);

	Py_INCREF(&ExecattrType);
	PyModule_AddObject(m, "execattr", (PyObject*)&ExecattrType);

	Py_INCREF(&UserattrType);
	PyModule_AddObject(m, "userattr", (PyObject*)&UserattrType);

	return m;

}
