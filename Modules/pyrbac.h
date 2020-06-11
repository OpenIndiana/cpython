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
 * RBAC bindings for python
 */
#ifndef PYRBAC_H
#define PYRBAC_H

#include <secdb.h>


#define PYRBAC_USER_MODE 1
#define PYRBAC_PROF_MODE 2
#define PYRBAC_ATTR_MODE 3
#define PYRBAC_NAM_MODE 4
#define PYRBAC_UID_MODE 5

PyTypeObject AuthattrType;
PyTypeObject ExecattrType;
PyTypeObject UserattrType;

#endif
