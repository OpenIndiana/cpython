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
 * Copyright (c) 2012, 2014, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef	_LIBPYTHON35_DB_32_H
#define	_LIBPYTHON35_DB_32_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/types.h>

/*
 * Define 32-bit Python data structures for use by the 64-bit debugger.  This
 * is so that a 64-bit debugger may properly examine a 32-bit process.
 *
 * In many cases, the debug library is only concerned with a few fields in the
 * Python structure.  In that case, the other ancillary fields are elided.
 */

typedef uint32_t uintptr32_t;
typedef int32_t Py_ssize32_t;

typedef struct _is32 {
	uintptr32_t	next;
	uintptr32_t	tstate_head;
} PyInterpreterState32;

typedef struct _ts32 {
	uintptr32_t	next;
	uintptr32_t	interp;
	uintptr32_t	frame;
} PyThreadState32;

#define	PyObject_HEAD32			\
	Py_ssize32_t	ob_refcnt;	\
	uintptr32_t	ob_type;

#define	PyObject_VAR_HEAD32		\
	PyObject_HEAD32			\
	Py_ssize32_t	ob_size;

typedef struct {
	PyObject_HEAD32
} PyObject32;

typedef struct {
	PyObject_VAR_HEAD32
} PyVarObject32;

typedef struct {
	PyObject_VAR_HEAD32
	int32_t		ob_shash;
	int		ob_sstate;
	char		ob_sval[1];
} PyBytesObject32;

#define	Py_SIZE32(ob)			(((PyVarObject32*)(ob))->ob_size)
#define	PyString_GET_SIZE32(op)		Py_SIZE32(op)
#define	PyString_AS_STRING32(op)	(((PyBytesObject32 *)(op))->ob_sval)

typedef struct {
	PyObject_VAR_HEAD32
	uintptr32_t	f_back;
	uintptr32_t	f_code;
	uintptr32_t	f_builtins;
	uintptr32_t	f_globals;
	uintptr32_t	f_locals;
	uintptr32_t	f_valuestack;
	uintptr32_t	f_stacktop;
	uintptr32_t	f_trace;
	uintptr32_t	f_exc_typpe, f_exc_value, f_exc_traceback;
	uintptr32_t	f_tstate;
	int		f_lasti;
	int		f_lineno;
} PyFrameObject32;

typedef struct {
	PyObject_HEAD32
	int		co_argcount;
	int		co_nlocals;
	int		co_stacksize;
	int		co_flags;
	uintptr32_t	co_code;
	uintptr32_t	co_consts;
	uintptr32_t	co_names;
	uintptr32_t	co_varnames;
	uintptr32_t	co_freevars;
	uintptr32_t	co_cellvars;
	uintptr32_t	co_filename;
	uintptr32_t	co_name;
	int		co_firstlineno;
	uintptr32_t	co_lnotab;
} PyCodeObject32;

#ifdef	__cplusplus
}
#endif

#endif	/* _LIBPYTHON35_DB_32_H */
