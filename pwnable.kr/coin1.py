from pwn import *

#count = 0

def binary_search(n):
	
	high = n 
	low = 0
	num = ""
	rev = 0
	send = -1

	while True:

		num = ""	
		mid = (low+high) / 2

		'''
		if send != -1:
			s.sendline(str(send))
		'''

		for i in range(low,mid+1):
			num += str(i) + " "
		s.sendline(num)
		
		rev = s.recv()
		
		if rev.find("Correct") > -1:
			break
		
		weight = int(rev)

		if weight % 10 != 0:
			high = mid
		#elif weight == 9:
			#send = num		
		else:
			low = mid+1
		
s = remote("pwnable.kr",9007)
count = 0

s.recv()
sleep(3)

for i in range(100):
	s.recvuntil("N=")
	N = int(s.recvuntil(" "))

	s.recvuntil("C=")

	C = int(s.recvuntil("\n"))

	binary_search(N)
	count+=1
	print "[*] " + str(count) + " level clear"

s.interactive()
