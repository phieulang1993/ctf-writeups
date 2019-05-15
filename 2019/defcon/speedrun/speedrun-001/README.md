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
