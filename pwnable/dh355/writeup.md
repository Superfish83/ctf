# DreamHack 355 (fho) - level 2

## Checksec
- Canary found
- Full RELRO
- NX enabled
- PIE enabled

## vulnerability
- Stack BOF + AAW + AAF

## strategy
- leak libc with stack BOF
- AAW -> overwrite __free_hook
- AAF -> trigger __free_hook
