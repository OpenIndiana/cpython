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
 * Copyright (c) 2012, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef	_LIBPYTHON35_DB_H
#define	_LIBPYTHON35_DB_H

#include <proc_service.h>

#ifdef	__cplusplus
extern "C" {
#endif

/* Agent is opaque to library's consumers.  */
typedef struct pydb_agent pydb_agent_t;

/*
 * Library's debug version is 1.  Changes to interface should increase this
 * number.
 */
#define	PYDB_VERSION	1

/* Agent creation/destruction routines */
extern	pydb_agent_t	*pydb_agent_create(struct ps_prochandle *P, int vers);
extern	void		pydb_agent_destroy(pydb_agent_t *py);

/* Used by callers that know they are looking at a PyFrameObject */
extern	int	pydb_get_frameinfo(pydb_agent_t *py, uintptr_t frame_addr,
    char *fbuf, size_t bufsz, int verbose);

/*
 * Used by callers that don't know if they're looking at PyFrameObject.
 * Checks PC for traceable functions.
 */
extern	int	pydb_pc_frameinfo(pydb_agent_t *py, uintptr_t pc,
    uintptr_t frame_addr, char *fbuf, size_t bufsz);

/* Iterator functions */
typedef struct pydb_iter pydb_iter_t;

extern	pydb_iter_t	*pydb_frame_iter_init(pydb_agent_t *py, uintptr_t addr);
extern	pydb_iter_t	*pydb_interp_iter_init(pydb_agent_t *py,
    uintptr_t addr);
extern	pydb_iter_t	*pydb_thread_iter_init(pydb_agent_t *py,
    uintptr_t addr);
extern	void		pydb_iter_fini(pydb_iter_t *iter);
extern	uintptr_t	pydb_iter_next(pydb_iter_t *iter);

#ifdef	__cplusplus
}
#endif

#endif	/* _LIBPYTHON35_DB_H */
