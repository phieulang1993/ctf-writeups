a="\xA0\xE3\xA6\xA1\xB0\xE0\x8C\xB0\xA1\xE7\xB0\xB8\xE0\xA1"
def sxor(s1,s2):
	return ''.join(chr(ord(a) ^ ord(b)) for a,b in zip(s1,s2))

print sxor(a,"\xd3"*len(a))
# s0urc3_cr4ck3r