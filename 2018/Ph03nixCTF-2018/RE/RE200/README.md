# RE200
**Category:** RE
**Points:** 200
## Writeup
```
$ file RE200.exe 
RE200.exe: PE32 executable (console) Intel 80386 (stripped to external PDB), for MS Windows
```
Coi sơ binary bài này mình thấy chương trình qua cái hàm nào đó rồi nó yêu cầu mình nhập 1 số vào, sau đó nó lấy 1 byte số đó xor với mem ở địa chỉ 0x408180 rồi chương trình sẽ call 0x408180

Phải đúng cái số thì mem nó mới ra đúng instruction để ra được flag, mình ngại tính với đoán nên mình code 1 file bat để bruteforce từ 0 -> 255.
```
echo 1 | RE200.exe
echo 2 | RE200.exe
echo 3 | RE200.exe
...
echo 131 | RE200.exe
echo 132 | RE200.exe
echo 133 | RE200.exe
echo 134 | RE200.exe
echo 135 | RE200.exe
echo 136 | RE200.exe
echo 137 | RE200.exe
echo 138 | RE200.exe
echo 139 | RE200.exe
echo 140 | RE200.exe
...
echo 250 | RE200.exe
echo 251 | RE200.exe
echo 252 | RE200.exe
echo 253 | RE200.exe
echo 254 | RE200.exe
echo 255 | RE200.exe
```
**Kết quả bruteforce:**
```
D:\CTF\CTFs\2018\Ph0nix\RE>echo 134   | RE200.exe
This challenge brought to you by nghiadtse05330
Give me your farvorite number:

D:\CTF\CTFs\2018\Ph0nix\RE>echo 135   | RE200.exe
This challenge brought to you by nghiadtse05330
Give me your farvorite number:

D:\CTF\CTFs\2018\Ph0nix\RE>echo 136   | RE200.exe
This challenge brought to you by nghiadtse05330
Give me your farvorite number:
Enter your name: There is nothing for you
D:\CTF\CTFs\2018\Ph0nix\RE>echo 137   | RE200.exe
This challenge brought to you by nghiadtse05330
Give me your farvorite number:
```

Vậy input nhập vào là 136.

Tiếp theo trace chương trình sau khi xor mem 0x408180

Chương trình yêu gọi fgets yêu cầu nhập name, rồi dùng strlen để check length nếu bằng 0x0E thì lấy name xor với 0xD3 rồi dùng strcmp so sánh với mem 0x408374, bằng thì xuất flag

Vậy mình lấy 0x0E bytes từ 0x408374 ra và xor với 0xD3 là ra name phù hợp.
```python
a="\xA0\xE3\xA6\xA1\xB0\xE0\x8C\xB0\xA1\xE7\xB0\xB8\xE0\xA1"
def sxor(s1,s2):
	return ''.join(chr(ord(a) ^ ord(b)) for a,b in zip(s1,s2))

print sxor(a,"\xd3"*len(a))
# s0urc3_cr4ck3r
```

**Flag:**
```
D:\CTF\CTFs\2018\Ph0nix\RE>RE200.exe
This challenge brought to you by nghiadtse05330
Give me your farvorite number:
136
Enter your name: s0urc3_cr4ck3r
Welcome 200 points for your brilliant
This is your flag: Ph03nix{s0urc3_cr4ck3r_r4t_d3p_tr4i}
```