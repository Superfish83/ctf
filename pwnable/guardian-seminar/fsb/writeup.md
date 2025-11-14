# Guardian Seminar: Simple Format String Bug

## checksec
- Partial RELRO
- No Canary
- No PIE
- NX Enabled

## vulnerability
- One AAW is possible via format string bug
- There is `win` function in `.text` section

## strategy
- PIE is not enabled

    -> overwrite return address of `vuln` function with the address of `win` function

    - We can leak neither libc nor stack address before perfoming AAW (single AAW/AAR only)
    
    -> overwrite the garbage pointer inside the local variable `buf[0x100]`. Overwrite only the least significant byte, and use it as the pointer to which we will perform AAW.

    - We still don't know if we are performing AAW to the right place, due to ASLR! -> Brute force (it is feasible since we changed only the least significant byte from a close enough address. The probability of getting it right is about 1/16)

## exploit

For example, the stack of `vuln` is organized like:

```
$rbp+0x08   -> 0x40122a     (return address of main)
$rbp        -> ...          (old rbp)

...


$rsp+0x28   -> 0x7ffda3fd67eo (garbage pointer) 
$rsp+0x20   -> ...
$rsp+0x18   -> ...
$rsp+0x10   -> ...
$rsp+0x08   -> ...            (start of buf[0x100])
$rsp        -> 0x401205     (return address of vuln)
```

The exploit code will send 0x29 bytes to the program make the stack into something like this:

```
$rbp+0x08   -> 0x40122a     (return address of main)
$rbp        -> ...          (old rbp)

...


$rsp+0x28   -> 0x7ffda3fd6708 (garbage pointer modified) 
$rsp+0x20   -> "AAAAAAAA"
$rsp+0x18   -> "AAAAAAAA"
$rsp+0x10   -> [format string]
$rsp+0x08   -> [format string]
$rsp        -> 0x401205     (return address of vuln)
```
The odds of the modified garbage pointer coinciding $rbp+0x08 is abbout 1/16. we write the desired address `0x4011b8`(start of `win`) to the pointed stack address. If succeeded (with 1/16 probability), we will get the shell.


## Failed Attempts

1. Overwrite `.got.plt` using AAW
    - impossible to exploit, since the functions in plt are never called again

2. Overwrite `.fini_array` using AAW
    - impposible, since Partial RELRO setting is on