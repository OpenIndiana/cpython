#!/usr/bin/python3.5

import dlpi
import sys
import time
import struct

#test listlink
linklist = dlpi.listlink()
print("Found %d links:" % len(linklist))
print(linklist)

#pick up the first data link for below testing
linkname = linklist[0]

#open link
print("opening link: " + linkname + "...")
testlink = dlpi.link(linkname)

#read some info of testlink
print("linkname is %s" % testlink.get_linkname())
print("link fd is %d" % testlink.get_fd())
mactype = testlink.get_mactype()
print("dlpi mactype is %d" % mactype)
print("after convert:")
print("\tmactype is %s" % dlpi.mactype(mactype))
print("\tiftype is %d" % dlpi.iftype(mactype))
print("\tarptype is %d" % dlpi.arptype(mactype))
bcastaddr = testlink.get_bcastaddr()
print("broadcast addr is: ", end=' ')
print(struct.unpack("BBBBBB",bcastaddr))
physaddr = testlink.get_physaddr(dlpi.FACT_PHYS_ADDR)
print("factory physical address is: ", end=' ')
print(struct.unpack("BBBBBB",physaddr))
print("current timeout value is %d" % testlink.get_timeout())
print("sdu is:", end=' ')
print(testlink.get_sdu())
print("qos select is:", end=' ')
print(testlink.get_qos_select())
print("qos range is:", end=' ')
print(testlink.get_qos_range())

#set some config value of testlink and read them again
print("setting current physiacal addr to aa:0:10:13:27:5")
testlink.set_physaddr('\xaa\0\x10\x13\x27\5')
physaddr = testlink.get_physaddr(dlpi.CURR_PHYS_ADDR)
print("current physical addr is: ", end=' ')
print(struct.unpack("BBBBBB",physaddr))
print("set timeout value to 6...")
testlink.set_timeout(6)
print("timeout value is %d" % testlink.get_timeout())

#test enable/disable multicast
print("enable/disable multicast address 1:0:5e:0:0:5")
testlink.enabmulti('\1\0\x5e\0\0\5')
testlink.disabmulti('\1\0\x5e\0\0\5')

#test bind
print("binding to SAP 0x9000...")
testlink.bind(0x9000)
print("sap is %x" % testlink.get_sap())
print("state is: %d"  % testlink.get_state())

#test send
print("sending broadcast loopback packet...")
testlink.send(bcastaddr, '\0\1\2\3\4\5')

#test notify functionality
arg = "notification callback arg"
def notify(arg, notes, value):
	print("NOTE_PROMISC_ON_PHYS notification received with arg: '%s'" % arg)
print("enabled notification on NOTE_PROMISC_ON_PHYS")
id = testlink.enabnotify(dlpi.NOTE_PROMISC_ON_PHYS, notify, arg) #enable notification
testlink.promiscon() #trigger the event (will be seen while receiving pkt below)

#test receive
print("testing receiving...")
try:
	testlink.recv(0, 0) #should see NOTE_PROMISC_ON_PHYS event here
except dlpi.error as err:
	errnum, errinfo = err
	if errnum == 10006:
		pass #timeout error is expected here
	else: #test fails if reach here
		print("test failed", end=' ')
		print(errnum, end=' ')
		print(err)

testlink.promiscoff()
testlink.disabnotify(id) #disable notification

#test unbind
print("unbinding...")
testlink.unbind()
print("sap is %x" % testlink.get_sap())
print("state is: %d"  % testlink.get_state())
