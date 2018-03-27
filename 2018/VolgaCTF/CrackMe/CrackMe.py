import subprocess
import time
import threading

import base64
import hashlib
from Crypto import Random
from Crypto.Cipher import AES
import thread

class myThread (threading.Thread):
	def __init__(self, key):
		threading.Thread.__init__(self)
		self.key = key
	def run(self):
		crack(self.key)


class AESCipher(object):
	def __init__(self, key): 
		self.bs = 16
		self.key = key
		
	def decrypt(self, enc):
		iv = enc[:AES.block_size]
		cipher = AES.new(self.key, AES.MODE_CBC, iv)
		return self._unpad(cipher.decrypt(enc[AES.block_size:]))

	def _pad(self, s):
		return s + (self.bs - len(s) % self.bs) * chr(self.bs - len(s) % self.bs)

	@staticmethod
	def _unpad(s):
		return s[:-ord(s[len(s)-1:])]

def crack(key):
	aes = AESCipher(key)
	if "volgactf" in aes.decrypt(enc).lower():
		print key.encode("hex")
		print aes.decrypt(enc)
		exit(1)
	

enc = open("CrackMe.txt","rb").read()
for i in xrange(256):
	print "i: %d" % i
	for i2 in xrange(256):
		print "i2: %d" % i2
		for i3 in xrange(256):
			for i4 in xrange(256):				
				key = chr(i)+chr(i2)+chr(i3)+chr(i4)
				key = key*4
				crack(key)

# VolgaCTF{my_little_cat_solved_this_much_faster}