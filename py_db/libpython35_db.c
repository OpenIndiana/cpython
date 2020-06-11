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
 * Copyright (c) 2012, 2015, Oracle and/or its affiliates. All rights reserved.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <gelf.h>

#include <Python.h>
#include <frameobject.h>

#include "libpython35_db.h"

struct pydb_agent {
	struct ps_prochandle *pdb_ph;
	int pdb_vers;
	int pdb_is_64bit;
	int pdb_datamodel;
};

typedef uintptr_t (*pdi_next_cb_t)(pydb_iter_t *);

struct pydb_iter {
	struct ps_prochandle *pdi_ph;
	uintptr_t pdi_current;
	pdi_next_cb_t pdi_nextf;
};

#define	LIBPYTHON	"libpython3.7m.so"

#define	MIN(x, y)	(((x) < (y)) ? (x) : (y))

/* Generic interface to helper functions */
static ssize_t pydb_strobj_readdata(pydb_agent_t *py, uintptr_t addr,
    unsigned char *buf, size_t buf_len);
static int pydb_getlno(pydb_agent_t *py, uintptr_t lnotab_addr, int firstline,
    int lastinst);
static int pydb_frameinfo(pydb_agent_t *py, uintptr_t addr, char *funcnm,
    size_t funcnm_sz, char *filenm, size_t filenm_sz, int *lineno);

/* datamodel specific implementation of helper functions */
static ssize_t pydb_strobj_readdata_native(pydb_agent_t *py, uintptr_t addr,
    unsigned char *buf, size_t buf_len);
static int pydb_frameinfo_native(pydb_agent_t *py, uintptr_t addr, char *funcnm,
    size_t funcnm_sz, char *filenm, size_t filenm_sz, int *lineno);

static ssize_t pydb_strobj_readstr(pydb_agent_t *py, uintptr_t addr, char *buf,
    size_t len);

/* Iterator function next routines.  Plugable, configured by iterator init */
static uintptr_t pydb_frame_iter_next(pydb_iter_t *iter);
static uintptr_t pydb_interp_iter_next(pydb_iter_t *iter);
static uintptr_t pydb_thread_iter_next(pydb_iter_t *iter);

static const char *strbasename(const char *s);

static const char *
strbasename(const char *s)
{
	const char *p = strrchr(s, '/');

	if (p == NULL)
		return (s);

	return (++p);
}

/* Agent creation / destruction routines */

pydb_agent_t *
pydb_agent_create(struct ps_prochandle *P, int vers)
{
	pydb_agent_t *py;
	int datamodel;

	if (vers != PYDB_VERSION) {
		errno = ENOTSUP;
		return (NULL);
	}

	if (ps_pdmodel(P, &datamodel) != PS_OK) {
		return (NULL);
	}

	py = (pydb_agent_t *)malloc(sizeof (pydb_agent_t));
	if (py == NULL) {
		return (NULL);
	}

	py->pdb_ph = P;
	py->pdb_vers = vers;
	py->pdb_datamodel = datamodel;
	py->pdb_is_64bit = 0;

	return (py);
}

void
pydb_agent_destroy(pydb_agent_t *py)
{
	if (py == NULL) {
		return;
	}

	free(py);
}

/* Helper functions */
static int
pydb_getlno(pydb_agent_t *py, uintptr_t lnotab_addr, int firstline,
    int lastinst)
{
	unsigned char lnotab[4096];
	ssize_t lnotab_len;
	int addr, line;
	int i;

	lnotab_len = pydb_strobj_readdata(py, lnotab_addr, lnotab,
	    sizeof (lnotab));
	if (lnotab_len < 0) {
		return (-1);
	}

	/*
	 * Python's line number algorithm is arcane. See here for details:
	 * http://svn.python.org/projects/python/trunk/Objects/lnotab_notes.txt
	 */

	line = firstline;
	for (addr = i = 0; i < lnotab_len; i += 2) {
		if (addr + lnotab[i] > lastinst) {
			break;
		}
		addr += lnotab[i];
		line += lnotab[i + 1];
	}

	return (line);
}

static ssize_t
pydb_asciiobj_readdata(pydb_agent_t *py, uintptr_t addr,
    unsigned char *buf, size_t buf_len)
{
	PyASCIIObject sobj;
	ssize_t obj_sz;
	ssize_t read_sz;
	psaddr_t asciiaddr;

	/*
	 * PyASCIIObjects are a type of Unicode string.  They are identified
	 * as follows:
	 * - sobj.state.compact == 1
	 * - sobj.state.ascii == 1
	 * - sobj.state.ready == 1
	 * The length of the string is stored in sobj.length.  The string
	 * itself follows the PyASCIIObject.
	 */

	if (ps_pread(py->pdb_ph, addr, &sobj, sizeof (PyASCIIObject))
	    != PS_OK) {
		return (-1);
	}

	if (!sobj.state.compact || !sobj.state.ascii || !sobj.state.ready) {
		return (-1);
	}

	obj_sz = (ssize_t)sobj.length;

	read_sz = MIN(obj_sz, (ssize_t)buf_len);
	asciiaddr = (psaddr_t)(addr + sizeof (PyASCIIObject));

	if (ps_pread(py->pdb_ph, asciiaddr, buf, (size_t)read_sz) != PS_OK) {
		return (-1);
	}

	return (read_sz);
}

static ssize_t
pydb_asciiobj_readstr(pydb_agent_t *py, uintptr_t addr, char *buf,
    size_t buf_len)
{
	ssize_t read_sz;

	read_sz = pydb_asciiobj_readdata(py, addr, (unsigned char *)buf,
	    buf_len);

	if (read_sz >= 0) {
		if (read_sz >= buf_len) {
			read_sz = buf_len - 1;
		}

		buf[read_sz] = '\0';
	}

	return (read_sz);
}

static ssize_t
pydb_strobj_readdata(pydb_agent_t *py, uintptr_t addr,
    unsigned char *buf, size_t buf_len)
{
	PyBytesObject sobj;
	ssize_t obj_sz;
	ssize_t read_sz;
	psaddr_t straddr;

	/*
	 * PyBytesObject are variable size.  The size of the PyBytesObject
	 * struct is fixed, and known at compile time; however, the size of the
	 * associated buffer is variable.  The char[1] element at the end of the
	 * structure contains the string, and the ob_size of the PyBytesObject
	 * indicates how much extra space was allocated to contain the string
	 * buffer at the object's tail.  Read in the fixed size portion of the
	 * object first, and then read the contents of the data buffer into the
	 * buffer passed by the caller.
	 */

	if (ps_pread(py->pdb_ph, addr, &sobj, sizeof (PyBytesObject))
	    != PS_OK) {
		return (-1);
	}

	/*
	 * If we want to emulate PyBytes_GET_SIZE() instead of just calling
	 * Py_SIZE() directly, we need to do a ps_pread() of Py_TYPE(&sobj).
	 * PyBytes_Check() will try to access the type structure, but the 
	 * address is not in the debugger's address space.
	 */
	obj_sz = (ssize_t)Py_SIZE(&sobj);

	read_sz = MIN(obj_sz, (ssize_t)buf_len);
	straddr = (psaddr_t)(addr + offsetof(PyBytesObject, ob_sval));

	if (ps_pread(py->pdb_ph, straddr, buf, (size_t)read_sz) != PS_OK) {
		return (-1);
	}

	return (read_sz);
}

/*
 * Most Python PyBytesObject contain strings, as one would expect.  However,
 * due to some sleazy hackery in parts of the Python code, some string objects
 * are used as buffers for binary data.  In the general case,
 * pydb_strobj_readstr() should be used to read strings out of string objects.
 * It wraps pydb_strobj_readdata(), which should be used by callers only when
 * trying to retrieve binary data.  (This routine does some string cleanup).
 */
static ssize_t
pydb_strobj_readstr(pydb_agent_t *py, uintptr_t addr, char *buf,
    size_t buf_len)
{
	ssize_t read_sz;

	read_sz = pydb_strobj_readdata(py, addr, (unsigned char *)buf, buf_len);

	if (read_sz >= 0) {
		if (read_sz >= buf_len) {
			read_sz = buf_len - 1;
		}

		buf[read_sz] = '\0';
	}

	return (read_sz);
}


static int
pydb_frameinfo(pydb_agent_t *py, uintptr_t addr, char *funcnm,
    size_t funcnm_sz, char *filenm, size_t filenm_sz, int *lineno)
{
	PyFrameObject fo;
	PyCodeObject co;
	ssize_t rc;

	if (ps_pread(py->pdb_ph, addr, &fo, sizeof (PyFrameObject))
	    != PS_OK) {
		return (-1);
	}

	if (ps_pread(py->pdb_ph, (uintptr_t)fo.f_code, &co,
	    sizeof (PyCodeObject)) != PS_OK) {
		return (-1);
	}

	rc = pydb_asciiobj_readstr(py, (uintptr_t)co.co_name, funcnm,
	    funcnm_sz);
	if (rc < 0) {
		return (-1);
	}

	rc = pydb_asciiobj_readstr(py, (uintptr_t)co.co_filename, filenm,
	    filenm_sz);
	if (rc < 0) {
		return (-1);
	}

	*lineno = pydb_getlno(py, (uintptr_t)co.co_lnotab, co.co_firstlineno,
	    fo.f_lasti);
	if (*lineno < 0) {
		return (-1);
	}

	return (0);
}

/* Functions that are part of the library's interface */

/*
 * Given the address of a PyFrameObject, and a buffer of a known size,
 * fill the buffer with a description of the frame.
 */
int
pydb_get_frameinfo(pydb_agent_t *py, uintptr_t frame_addr, char *fbuf,
    size_t bufsz, int verbose)
{
	char funcname[1024];
	char filename[1024];
	char *fn;
	int lineno;
	int length = (py->pdb_is_64bit ? 16 : 8);
	int rc;

	rc = pydb_frameinfo(py, frame_addr, funcname, sizeof (funcname),
	    filename, sizeof (filename), &lineno);
	if (rc < 0) {
		return (-1);
	}

	if (!verbose) {
		fn = (char *)strbasename(filename);
	} else {
		fn = filename;
	}

	(void) snprintf(fbuf, bufsz, "%0.*lx %s:%d %s()\n", length,
	    frame_addr, fn, lineno, funcname);

	return (0);
}

/*
 * Return a description about a PyFrameObject, if the object is
 * actually a PyFrameObject.  In this case, the pc argument is checked
 * to make sure that it came from a function that takes a PyFrameObject
 * as its first (argv[0]) argument.
 */
int
pydb_pc_frameinfo(pydb_agent_t *py, uintptr_t pc, uintptr_t frame_addr,
    char *fbuf, size_t bufsz)
{
	char funcname[1024];
	char filename[1024];
	int lineno;
	int rc;
	ps_sym_t psym;

	/*
	 * If PC doesn't match PyEval_EvalFrameEx in either libpython
	 * or the executable, don't decode it.
	 */
	if (ps_pglobal_sym(py->pdb_ph, LIBPYTHON, "PyEval_EvalFrameEx", &psym)
	    != PS_OK) {
		return (-1);
	}

	/* If symbol found, ensure that PC falls within PyEval_EvalFrameEx. */
	if (pc < psym.st_value || pc > psym.st_value + psym.st_size) {
		return (-1);
	}

	rc = pydb_frameinfo(py, frame_addr, funcname, sizeof (funcname),
	    filename, sizeof (filename), &lineno);
	if (rc < 0) {
		return (-1);
	}

	(void) snprintf(fbuf, bufsz, "[ %s:%d (%s) ]\n", filename, lineno,
	    funcname);

	return (0);
}

/*
 * Walks the list of PyInterpreterState objects.  If caller doesn't
 * supply address of list, this method will look it up.
 */
pydb_iter_t *
pydb_interp_iter_init(pydb_agent_t *py, uintptr_t addr)
{
	pydb_iter_t *itr;
	uintptr_t i_addr;
	int rc;

	if (addr == 0) {
		rc = ps_pglobal_lookup(py->pdb_ph, LIBPYTHON, "interp_head",
		    (psaddr_t *)&addr);
		if (rc != PS_OK) {
			return (NULL);
		}
	}

	if (ps_pread(py->pdb_ph, (uintptr_t)addr, &i_addr, sizeof (uintptr_t))
	    != PS_OK) {
		return (NULL);
	}

	itr = malloc(sizeof (pydb_iter_t));
	if (itr == NULL) {
		return (NULL);
	}

	itr->pdi_ph = py->pdb_ph;
	itr->pdi_current = i_addr;
	itr->pdi_nextf = pydb_interp_iter_next;

	return (itr);
}

static uintptr_t
pydb_interp_iter_next(pydb_iter_t *iter)
{
	PyInterpreterState st;
	uintptr_t cur;

	cur = iter->pdi_current;

	if (cur == 0) {
		return (cur);
	}

	if (ps_pread(iter->pdi_ph, cur, &st, sizeof (PyInterpreterState))
	    != PS_OK) {
		iter->pdi_current = 0;
		return (0);
	}

	iter->pdi_current = (uintptr_t)st.next;

	return (cur);
}

/*
 * Walk a list of Python PyFrameObjects.  The addr argument must be
 * the address of a valid PyThreadState object.
 */
pydb_iter_t *
pydb_frame_iter_init(pydb_agent_t *py, uintptr_t addr)
{
	pydb_iter_t *itr;
	PyThreadState ts;

	if (ps_pread(py->pdb_ph, (uintptr_t)addr, &ts, sizeof (PyThreadState))
	    != PS_OK) {
		return (NULL);
	}

	itr = malloc(sizeof (pydb_iter_t));
	if (itr == NULL) {
		return (NULL);
	}

	itr->pdi_ph = py->pdb_ph;
	itr->pdi_current = (uintptr_t)ts.frame;
	itr->pdi_nextf = pydb_frame_iter_next;

	return (itr);
}

static uintptr_t
pydb_frame_iter_next(pydb_iter_t *iter)
{
	PyFrameObject fo;
	uintptr_t cur;

	cur = iter->pdi_current;

	if (cur == 0) {
		return (cur);
	}

	if (ps_pread(iter->pdi_ph, cur, &fo, sizeof (PyFrameObject))
	    != PS_OK) {
		iter->pdi_current = 0;
		return (0);
	}

	iter->pdi_current = (uintptr_t)fo.f_back;

	return (cur);
}

/*
 * Walk a list of Python PyThreadState objects.  The addr argument must be
 * the address of a valid PyInterpreterState object.
 */
pydb_iter_t *
pydb_thread_iter_init(pydb_agent_t *py, uintptr_t addr)
{
	pydb_iter_t *itr;
	PyInterpreterState is;

	if (ps_pread(py->pdb_ph, (uintptr_t)addr, &is,
	    sizeof (PyInterpreterState)) != PS_OK) {
		return (NULL);
	}

	itr = malloc(sizeof (pydb_iter_t));
	if (itr == NULL) {
		return (NULL);
	}

	itr->pdi_ph = py->pdb_ph;
	itr->pdi_current = (uintptr_t)is.tstate_head;
	itr->pdi_nextf = pydb_thread_iter_next;

	return (itr);
}

static uintptr_t
pydb_thread_iter_next(pydb_iter_t *iter)
{
	PyThreadState ts;
	uintptr_t cur;

	cur = iter->pdi_current;

	if (cur == 0) {
		return (cur);
	}

	if (ps_pread(iter->pdi_ph, cur, &ts, sizeof (PyThreadState)) != PS_OK) {
		iter->pdi_current = 0;
		return (0);
	}

	iter->pdi_current = (uintptr_t)ts.next;

	return (cur);
}


uintptr_t
pydb_iter_next(pydb_iter_t *iter)
{
	return (iter->pdi_nextf(iter));
}

void
pydb_iter_fini(pydb_iter_t *iter)
{
	if (iter == NULL) {
		return;
	}

	free(iter);
}
