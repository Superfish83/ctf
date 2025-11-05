# Guardian Seminar: Baby-Heap

## checksec
- Full RELRO
- NX Enabled
- PIE Enabled
- Canary Found

## vulnerability
- UAF, Double Free

## strategy
- **how to leak libc?** -> using unsorted bin
- **how to pwn?** -> using `__free_hook` in libc 2.27

## exploit
1. leak libc
2. write the onegadget to a freed chunk (UAF)
3. alloc -> free -> free, to write onegadget to heap
4. free() to trigger onegadget
5. PROFIT!!!!!