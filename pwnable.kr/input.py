from pwn import *

argvs = []

for i in range(0,100):
	argvs.append(i)

argvs[ord("A")] = "\x00"
argvs[ord("B")] = "\x20\x0a\x0d"
argvs[ord("C")] = "1234"

f = open("asdf","w")
f.write("\x00\x0a\x02\xff")
f.close()

envs = {"\xde\xad\xbe\xef" : "\xca\xfe\xba\xbe"}

f = open("/home/input2/\x0a","w")
f.write("\x00\x00\x00\x00")
f.close()

s = process(executable = "/home/input2/input",argv = argvs,stderr = open("asdf"), env = envs)
#.recvuntil("Stage 4 clear!\n")

p = remote("127.0.0.1",1234)
s.send("\xde\xad\xbe\xef")

s.interactive()
