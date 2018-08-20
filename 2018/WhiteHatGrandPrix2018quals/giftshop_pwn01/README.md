# pwn01
```
nc pwn01.grandprix.whitehatvn.com 26129
file: material.grandprix.whitehatvn.com/pwn01
```
## Dịch ngược và tìm lỗi

Bài cho ta khá nhiều file:
1. giftshop
2. ptrace_64
3. ptrace_64.cpp
4. blacklist.conf
5. run.sh
6. menu.txt

Đọc run.sh ta thấy chương trình chạy dưới binary ptrace_64
```
./ptrace_64 ./giftshop gift 1 60 50 blacklist.conf
```
Đọc source ptrace_64.cpp ta thấy chương trình load vào các tham số:
* ./giftshop: đường dẫn tới binary sẽ thực thi
* gift: binary giftshop sẽ chạy dưới quyền của username gift
* 1: global_cpu_time_limit
* 60: global_real_time_limit
* 50: memLimit
* blacklist.conf: đường dẫn tới file blacklist các syscall.

Nội dung file blacklist.conf:
```
7
56
57
58
59
62
200
234
1
/home/gift/flag.txt
```

Hiểu nôm na là ptrace_64 sẽ chạy **giftshop** với quyền của user **gift** và trace các syscall để chặn các syscall trong file **blacklist.conf**, ngoài ra ptrace_64 còn chặn sys_open, sys_openat với đường dẫn /home/gift/flag.txt.

Dò bảng [syscall cho x86_64](http://blog.rchapman.org/posts/Linux_System_Call_Table_for_x86_64/) ta thấy các syscall bị chặn bao gồm:
* 7: sys_poll
* 56: sys_clone
* 57: sys_fork
* 58: sys_vfork
* 59: sys_execve
* 62: sys_kill
* 200: sys_tkill
* 234: sys_tgkill
* 1: sys_write

### Phân tích file giftshop:
checksec ta thấy chương trình có các cờ NX enabled, PIE enabled.
Coi sơ chương trình qua IDA ta dễ dàng nhận thấy chương trình không có hàm _stack_chk_fail và phát hiện lỗi **bufferoverflow** qua hàm ReadStr tại offset 0x1FEC.
```c
__int64 __fastcall readStr(const char *buff, int size)
{
  size_t len; // rdx
  __int64 result; // rax

  __isoc99_scanf("%s", buff);
  buff[strlen(buff)] = 0;
  len = strlen(buff);
  result = size;
  if ( len > size )
    Quit();
  return result;
}
```
Ta có thể bypass check bằng cách nhập null byte để strlen(buff) <= size.

Hàm main gọi hàm readInt (offset 0x2052) để chọn menu ta thấy hàm sử dụng hàm ReadStr với buff nằm tại stack nên ta có thể thực thi stackoverflow tại đây (do không có _stack_chk_fail)
```c
__int64 readInt()
{
  char nptr; // [rsp+0h] [rbp-10h]
  int v2; // [rsp+Ch] [rbp-4h]

  readStr(&nptr, 4);
  v2 = atoi(&nptr);
  if ( v2 <= 0 || v2 > 256 )
    Quit();
  return v2;
}
```

## Ý tưởng và giải quyết
Ta thực hiện ghi shellcode vào RECVNAME (offset 0x203120) trên BSS.
Sau đó ta stackoverflow để ROP về mprotect nhằm tạo quyền cho vùng nhớ BSS có quyền read, write và execute sau đó nhảy về thực thi shellcode trên đó.

Mục tiêu tiếp theo là viết shellcode làm sao để bypass được ptrace, ta có 1 số ý tưởng:
1. Sử dụng sys_symlink để bypass sys_open nhưng ý tưởng này thất bại vì ptrace_64.cpp sử dụng hàm realpath để kiểm tra đường dẫn thực sự của file sẽ open.
2. Sử dụng stub_execveat: có thể thành công vì syscall này không nằm trong danh sách blacklist syscall.
3. Switch mode sang x86, sau khi switch sẽ bypass được các syscall number bị chặn nhằm thực thi sys_execve("/bin/sh")

### Tiến hành thực hiện theo ý tưởng thứ 3:

Ta thấy các vùng nhớ được cấp phát đều lớn hơn 4 bytes (32 bits) nên ta cần mmap 1 vùng nhớ nhỏ hơn 4 bytes để setup cho các thanh ghi esp và eip của chương trình sau khi thực hiện switch.
Ta thực hiện *mmap(0x40000, 0x1000, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0)* rồi read shellcode vào đó sau đó thực hiện retf với esp+0x4 là 0x23 (x86) để switch mode và nhảy về vùng chứa shellcode.

### Payload exploit
[giftshop.py](https://github.com/phieulang1993/ctf-writeups/blob/master/2018/WhiteHatGrandPrix2018quals/giftshop_pwn01/giftshop.py)