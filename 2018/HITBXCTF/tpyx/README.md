```
Fix IDAT chunk length + CRC:
IDAT:
	Length: 1164470
	CRC: 6a0412ff
```
```
$ zsteg ./e47c7307-b54c-4316-9894-5a8daec738b4.png 
extradata:imagedata .. file: zlib compressed data
    00000000: 78 da 5d 50 89 6d 45 31  08 5b c9 dc 64 9c 04 5e  |x.]P.mE1.[..d..^|
    00000010: f6 1f a1 fc 43 aa 5a a4  28 60 c0 06 24 62 9f da  |....C.Z.(`..$b..|
    00000020: 97 83 0a 80 24 df e5 b5  48 f0 d7 e2 1f 20 85 87  |....$...H.... ..|
    00000030: 55 b1 4a 79 dd 3e c8 2b  f4 9c 62 71 3a 02 f2 0b  |U.Jy.>.+..bq:...|
    00000040: dd b1 36 02 29 10 d1 f2  ec d6 e8 23 29 8f 9e 60  |..6.)......#)..`|
    00000050: f5 5d bb 33 d4 51 0d 9c  ed 5c 77 3f 9e 86 a4 e4  |.].3.Q...\w?....|
    00000060: ed cb 38 36 08 0a 1f 41  c2 7a 8f 10 38 e3 03 cc  |..86...A.z..8...|
    00000070: 83 5f 9a 98 b0 4d 10 75  62 df 33 0c 65 7b 64 9d  |._...M.ub.3.e{d.|
    00000080: 47 76 72 04 b3 7e 8f 4c  df 57 5c 1c f3 27 86 bd  |Gvr..~.L.W\..'..|
    00000090: c4 ce 92 ef 72 06 22 1a  7e f8 28 fa dc c3 a7 de  |....r.".~.(.....|
    000000a0: e3 93 24 7e d5 bf bc 54  3d 57 6c 2e d6 c3 3f a7  |..$~...T=Wl...?.|
    000000b0: fa e2 8f fb 7a d2 bd a9  47 99 f4 83 27 ee ad ee  |....z...G...'...|
    000000c0: e5 f2 c5 6d f6 79 e3 bf  46 13 88 1a 05 bb e8 35  |...m.y..F......5|
    000000d0: f3 16 b7 70 0a e3 63 1e  a6 6c 29 e9 c1 47 d7 b4  |...p..c..l)..G..|
    000000e0: 87 b4 f4 0f c3 ab 68 44                           |......hD        |
```
```
$ pigz -d -i ./tpyx.zz
```
```
$ python -c 'data=open("tpyx","rb").read().decode("hex");open("tpyx2","wb").write(data)'
```
```
$ cat tpyx2 | xxd
00000000: 377a bcaf 271c 0003 82f9 6c91 3000 0000  7z..'.....l.0...
00000010: 0000 0000 7300 0000 0000 0000 3c0e 2440  ....s.......<.$@
00000020: 9c42 9fdb 08f3 1ebc 2361 b301 6f04 a79a  .B......#a..o...
00000030: 0708 3033 4c68 dd47 db38 3e4b 7246 acad  ..03Lh.G.8>KrF..
00000040: 8746 0cd0 0ba6 2cfa e685 0818 2a69 527a  .F....,.....*iRz
00000050: 0104 0600 0109 3000 070b 0100 0224 06f1  ......0......$..
00000060: 0701 0a53 07cb 7afb faec 5aa0 7623 0301  ...S..z...Z.v#..
00000070: 0105 5d00 0001 0001 000c 2c27 0008 0a01  ..].......,'....
00000080: c35b 9330 0000 0501 110b 0066 006c 0061  .[.0.......f.l.a
00000090: 0067 0000 0012 0a01 0000 844b f357 1cd1  .g.........K.W..
000000a0: 0113 0a01 0000 e669 e866 d1d3 0114 0a01  .......i.f......
000000b0: 0080 ffcd d963 d1d3 0115 0601 0080 0000  .....c..........
000000c0: 0000 0018 0034 5172 634f 556d 3657 6175  .....4QrcOUm6Wau
000000d0: 2b56 7542 5838 672b 4950 673d 3d         +VuBX8g+IPg==

```
```
$ 7z x tpyx2
7-Zip [64] 9.20  Copyright (c) 1999-2010 Igor Pavlov  2010-11-18
p7zip Version 9.20 (locale=en_US.UTF-8,Utf16=on,HugeFiles=on,1 CPU)

Processing archive: tpyx2


Enter password (will not be echoed) :4QrcOUm6Wau+VuBX8g+IPg==
Extracting  flag

Everything is Ok

Size:       39
Compressed: 221
```

```
$ cat flag 
HITB{0c88d56694c2fb3bcc416e122c1072eb}
```