# RE350
**Category:** RE
**Points:** 350
## Writeup
```
$ file chall-95464f47e71ccb883149755d7a3573bb 
chall-95464f47e71ccb883149755d7a3573bb: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=ba487562699109f09e6273e0fbcc7ed1f81ab161, stripped
```

Coi sơ qua binary bài này thì mình thấy là nó yêu cầu nhập flag 0x45 bytes vào agrument rồi nó qua cái hàm encode rồi xor với cái mem 0x601058 rồi kiểm tra tổng của các phép xor nếu bằng 0 thì báo flag đúng.
Vô ngó hàm encode thì ta thấy nó lấy input của ta add với 1 byte X nào đó rồi đưa lại 1 byte vào input, mà cái byte X đó lấy ra từ 0x601060 và cộng trừ nhân chia gì đó.

Debug đặt breakpoint ở 0x400772 ta thấy những byte X đó là như sau: "\xffkey-is-wtfkey-is-wtfkey-is-wtfkey-is-wtfkey-is-wtfkey-is-wtfkey-is-wtf..."

Vậy là ez rồi.

Viết lại thuật toán bằng python:
```python
encoded = "\x56\xd0\xd1\xe5\x4d\xcd\xe2\x9b\xdc\x94\xae\x9f\xbd\xa9\x9f\x8a\x93\x86\xe6\xe9\xd8\x8b\xcb\xe5\x8e\xd0\xad\x4d\xc7\xdc\x96\x9e\xd3\xe2\xa5\xe4\xc5\x60\xcd\xa7\xb8\xa0\x98\xd8\x60\xb7\xba\x5e\xc5\xa7\x99\xbd\x96\xc7\x74\xc8\xa4\x62\xd6\xca\x99\xbd\xbe\xd8\x73\xbe\xc1\xaa\x00"

key = "\xff"+"key-is-wtf"*7
flag = ""
for i in xrange(0, 68):
	e = ord(encoded[i])
	k = ord(key[i])
	flag += chr(((e+0x100)-k)&0xff)
print flag
```

**Flag:**
```$ python chall-95464f47e71ccb883149755d7a3573bb.py 
Well done H4X0r! Your flag: Ph03nix{R3V3R53_3NG1N33R1NG_15_V3RY_FUN}
```
 