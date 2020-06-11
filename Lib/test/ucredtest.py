#!/usr/bin/python3.7

import ucred
import os

uc = ucred.get(os.getpid())

print("pid = %d" % uc.getpid())
print("euid = %d" % uc.geteuid())
print("ruid = %d" % uc.getruid())
print("suid = %d" % uc.getsuid())
print("egid = %d" % uc.getegid())
print("rgid = %d" % uc.getrgid())
print("sgid = %d" % uc.getsgid())
print("zoneid = %d" % uc.getzoneid())
print("projid = %d" % uc.getprojid())
print("groups = %s" % uc.getgroups())
print("label = %s" % uc.getlabel())

print("getpflags(0x1) = %d" % uc.getpflags(0x1))
print("getpflags(0x2) = %d" % uc.getpflags(0x2))
print("has_priv(Effective, proc_fork) = %d" % uc.has_priv("Effective", "proc_fork"))
print("has_priv(Permitted, proc_fork) = %d" % uc.has_priv("Permitted", "proc_fork"))
print("has_priv(Inheritable, proc_fork) = %d" % uc.has_priv("Inheritable", "proc_fork"))
print("has_priv(Limit, file_setid) = %d" % uc.has_priv("Limit", "file_setid"))
print("has_priv(Effective, file_setid) = %d" % uc.has_priv("Effective", "file_setid"))
try:
    uc.has_priv("Effective", "proc_bork")
except OSError as e:
    print(e)
try:
    uc.has_priv("Defective", "proc_fork")
except OSError as e:
    print(e)
try:
    uc.has_priv("Defective", "proc_bork")
except OSError as e:
    print(e)

del uc
uc = ucred.ucred()
try:
    uc.getpid()
except OSError as e:
    print(e)
