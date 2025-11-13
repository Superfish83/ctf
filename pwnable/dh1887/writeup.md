# DreamHack 1887 (kidheap) - level 5

## Checksec
- Canary found
- NX
- PIE
- Full RELRO

## Vulnerability

UaF (call delete_note twice, then the freed memory becomes accessible)
