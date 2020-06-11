#!/usr/bin/python3.7
#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License (the "License").
# You may not use this file except in compliance with the License.
#
# You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
# or http://www.opensolaris.org/os/licensing.
# See the License for the specific language governing permissions
# and limitations under the License.
#
# When distributing Covered Code, include this CDDL HEADER in each
# file and include the License file at usr/src/OPENSOLARIS.LICENSE.
# If applicable, add the following below this CDDL HEADER, with the
# fields enclosed by brackets "[]" replaced with your own identifying
# information: Portions Copyright [yyyy] [name of copyright owner]
#
# CDDL HEADER END
#

# Copyright (c) 2011, Oracle and/or its affiliates. All rights reserved.

import privileges
import rbac
import os
import sys
import tempfile

# privileges tests

def test_setppriv():
    amchild = os.fork()
    if amchild == 0:
        if privileges.setppriv(privileges.PRIV_OFF, privileges.PRIV_EFFECTIVE, 
            ['proc_fork']):
            try:
                os.fork()
                sys.exit(1)
            except OSError as e:
                sys.exit(0)

    child = os.wait()
    if child[1] is not 0:
        print("setppriv. Bad exit status from pid %i\n" % child[0])
        return False
    return True

def test_getppriv():
    if 'proc_fork' in privileges.getppriv(privileges.PRIV_LIMIT):
        return True
    print("getppriv or PRIV_PROC_FORK not in PRIV_LIMIT.\n")
    return False

def test_priv_ineffect():
    if privileges.priv_ineffect('proc_fork'):
        return True
    print("priv_ineffect or PRIV_PROC_FORK not in effect\n")
    return False

# authattr tests

def test_chkauthattr():
    try:
        a = rbac.authattr()
    except Exception as e:
        print("Could not instantiate authattr object: %s\n" % e)
        return False
    try:
        res = a.chkauthattr('solaris.*', 'root')
    except Exception as e:
        print("chkauthattr failed: %s\n" % e)
        return False
    if not res:
        print("chkauthattr failed or \'root\' lacks \'solaris.*\'\n")
        return False
    return True

def test_getauthattr():
    try:
        a = rbac.authattr()
    except Exception as e:
        print("Could not instantiate authattr object: %s\n" % e)
        return False
    try:
        res = a.getauthattr()
    except Exception as e:
        print("getauthattr failed: %s\n" % e)
        return False
    if not 'name' in list(res.keys()):
        print("getauthattr failed\n")
        return False
    return True

def test_getauthnam():
    try:
        a = rbac.authattr()
    except Exception as e:
        print("Could not instantiate authattr object: %s\n" % e)
        return False
    try:
        res = a.getauthnam('solaris.')
    except Exception as e:
        print("getauthnam failed: %s\n" % e)
        return False
    if not res:
        print("getauthnam failed or \'solaris.\' not in auth_attr(4)\n")
        return False
    return True

def test_authattr_iter():
    try:
        a = rbac.authattr()
    except Exception as e:
        print("Could not instantiate authattr object: %s\n" % e)
        return False
    res = next(a)
    if not 'name' in list(res.keys()) or type(a) != type(a.__iter__()):
        print("authattr object is not an iterable\n")
        return False
    return True

# execattr tests

def test_getexecattr():
    try:
        a = rbac.execattr()
    except Exception as e:
        print("Could not instantiate execattr object: %s\n" % e)
        return False
    try:
        res = a.getexecattr()
    except Exception as e:
        print("getexecattr failed: %s\n" % e)
        return False
    if not 'name' in list(res.keys()):
        print("getexecattr failed\n")
        return False
    return True

def test_getexecuser():
    try:
        a = rbac.execattr()
    except Exception as e:
        print("Could not instantiate execattr object: %s\n" % e)
        return False
    try:
        res = a.getexecuser("root", "act", "*;*;*;*;*")
    except Exception as e:
        print("getexecuser failed: %s\n" % e)
        return False
    if not res:
        print("getexecuser failed or \'root\' not assigned to \'act\', " \
            "\'*;*;*;*;*\' \n")
        return False
    return True


def test_getexecprof():
    try:
        a = rbac.execattr()
    except Exception as e:
        print("Could not instantiate execattr object: %s\n" % e)
        return False
    try:
        res = a.getexecprof("All", "cmd", "*")
    except Exception as e:
        print("getexecprof failed: %s\n" % e)
        return False
    if not res:
        print("getexecprof failed or \'All\' not granted \'cmd\' : \'*\'\n")
        return False
    return True

def test_execattr_iter():
    try:
        a = rbac.execattr()
    except Exception as e:
        print("Could not instantiate execattr object: %s\n" % e)
        return False
    res = next(a)
    if not 'name' in list(res.keys()) or type(a) != type(a.__iter__()):
        print("execattr object is not an iterable\n")
        return False
    return True

# userattr tests

def test_getuserattr():
    try:
        a = rbac.userattr()
    except Exception as e:
        print("Could not instantiate userattr object: %s\n" % e)
        return False
    try:
        res = a.getuserattr()
    except Exception as e:
        print("getuserattr failed: %s\n" % e)
        return False
    if not 'name' in list(res.keys()):
        print("getuserattr failed\n")
        return False
    return True

def test_fgetuserattr():
    temp = tempfile.NamedTemporaryFile()
    temp.write("user::::profiles=Software Installation;roles=foo;"\
        "auths=solaris.foo.bar")
    temp.seek(0)
    try:
        a = rbac.userattr()
    except Exception as e:
        print("Could not instantiate userattr object: %s\n" % e)
        return False
    try:
        res = a.fgetuserattr(temp.name)
        temp.close()    
    except Exception as e:
        print("fgetuserattr failed: %s\n" % e)
        temp.close()
        return False
    if not 'name' in list(res.keys()):
        print("fgetuserattr failed\n")
        return False
    return True

def test_getuseruid():
    try:
        a = rbac.userattr()
    except Exception as e:
        print("Could not instantiate userattr object: %s\n" % e)
        return False
    try:
        res = a.getuseruid(0)
    except Exception as e:
        print("getusernam failed: %s\n" % e)
        return False
    if not 'name' in res:
        print("getusernam failed or no uid 0\n")
        return False
    return True

def test_getusernam():
    try:
        a = rbac.userattr()
    except Exception as e:
        print("Could not instantiate userattr object: %s\n" % e)
        return False
    try:
        res = a.getusernam('root')
    except Exception as e:
        print("getusernam failed: %s\n" % e)
        return False
    if not 'name' in res:
        print("getusernam failed or no \'root\' user\n")
        return False
    return True

def test_userattr_iter():
    try:
        a = rbac.userattr()
    except Exception as e:
        print("Could not instantiate userattr object: %s\n" % e)
        return False
    res = next(a)
    if not 'name' in list(res.keys()) or type(a) != type(a.__iter__()):
        print("userattr object is not an iterable\n")
        return False
    return True

if not test_setppriv() or not test_getppriv() or not test_priv_ineffect():
    print("*** Failures detected in privileges module\n")    
    sys.exit(1)

if not test_getauthattr() or not test_chkauthattr() or not test_getauthnam() \
    or not test_authattr_iter:
    print("*** Failures detected in rbac.authattr\n")
    sys.exit(1)

if not test_getexecattr() or not test_getexecuser() or not test_getexecprof() \
    or not test_execattr_iter():
    print("*** Failures detected in rbac.execattr\n")
    sys.exit(1)

if not test_getuserattr() or not test_fgetuserattr() or not test_getusernam()\
    or not test_getuseruid() or not test_userattr_iter():
    print("*** Failures detected in rbac.userattr\n")
    sys.exit(1)
