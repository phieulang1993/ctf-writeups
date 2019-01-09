# sandbox
```
Sơ bộ về chương trình các bạn có thể đọc tại các writeup:
https://blog.efiens.com/tetctf-2/
https://medium.com/@nghthach98/write-up-for-pwnable-challenges-tetctf-2019-a74eb177518e
```
Ở đây mình sẽ chỉ 1 cách để các bạn tìm được hàm _dl_make_stack_executable nhanh hơn.

ta code 1 chương trình đơn giản như sau:
```c
#include<stdio.h>
#include<stdlib.h>

int main(){
	printf("ledangquynhnhu");
}
```
Compile:
```
gcc test.c -o test -static
```

Mở bằng IDA tìm hàm _dl_make_stack_executable.
```c
unsigned int __fastcall dl_make_stack_executable(_QWORD *a1)
{
  __int64 v1; // rdx
  _QWORD *v2; // rax
  signed __int64 v3; // rdi
  _QWORD *v4; // rbx
  unsigned int result; // eax

  v1 = *a1;
  v2 = a1;
  v3 = *a1 & -dl_pagesize;
  if ( v1 != _libc_stack_end )
    return 1;
  v4 = v2;
  result = mprotect(v3, dl_pagesize, _stack_prot);
  if ( result )
    return __readfsdword(0xFFFFFFD0);
  *v4 = 0LL;
  dl_stack_flags |= 1u;
  return result;
}```
click double vào `_stack_prot` ta thấy biến này nằm ở cuối segment `.data.rel.ro` và có giá trị là `0x1000000`
Xrefs _stack_prot ta thấy chỉ có 2 hàm dùng tới nó là `_dl_map_object_from_fd_constprop_9` và `_dl_make_stack_executable`
Trong đó `_dl_make_stack_executable` sử dụng duy nhất 1 tham số để so sánh với `_libc_stack_end`

Ta thấy trong chương trình chỉ có 1 segment `.data.rel.ro`
Áp dụng sang trường hợp binary `program` của bài ta dùng shift f7 trên IDA để mở danh sách các segment, dò xuống ta click vào segment LOAD tại địa chỉ 0x6B8EF4 nằm ngay dưới segment `.data.rel.ro` lăn chuột lên chút ta thấy ngay `.data.rel.ro:00000000006B8EF0 dword_6B8EF0    dd 1000000h`
Như vậy `dword_6B8EF0` chính là `_stack_prot`, rename lại rồi xrefs ta thấy có 2 hàm dùng tới `_stack_prot` là `sub_476560` và `sub_47F780`
Xem qua 2 hàm thì chỉ có `sub_47F780` sử dụng 1 tham số nên xác định hàm này là `_dl_make_stack_executable`
```c
unsigned int __fastcall dl_make_stack_executable(_QWORD *a1)
{
  _QWORD *v1; // rbx
  __int64 v2; // rdx
  __int64 v3; // rdi
  unsigned int result; // eax

  v1 = a1;
  v2 = *a1;
  v3 = *a1 & -qword_6BA1F8;
  if ( v2 != qword_6B8AB0 )
    return 1;
  result = sub_44A0C0(v3, qword_6BA1F8, stack_prot);
  if ( result )
    return __readfsdword(0xFFFFFFC0);
  *v1 = 0LL;
  dword_6BA1E8 |= 1u;
  return result;
}```
`a1` được so sánh với `qword_6B8AB0` => `qword_6B8AB0` chính là `_libc_stack_end`
Vậy ta đã có đủ dữ kiện để dùng được `_dl_make_stack_executable`

Lần sau không cần phải compile kiểm tra nữa mà ta cứ mở IDA lên tìm segment `LOAD` ngay dưới `.data.rel.ro` là tìm được `stack_prot` là tìm được `_dl_make_stack_executable`
