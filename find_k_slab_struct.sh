#!/bin/bash

START=0xffffffff82700000
END=0xffffffff82800000
STEP=8
TARGET_PTR_LE="50ef7582ffffffff"  # Little-endian hex of 0xffffffff8275ef50

hex_to_dec() {
    printf "%d\n" "$((16#$1))"
}

dec_to_hex() {
    printf "0x%x\n" "$1"
}

cur=$(hex_to_dec ${START#0x})
end=$(hex_to_dec ${END#0x})

while [ "$cur" -lt "$end" ]; do
    addr=$(dec_to_hex "$cur")

    raw=$(kvm_prober readkvmem "$addr" 8 2>/dev/null | grep -o '[0-9a-fA-F]\{16\}')
    if [[ "$raw" == "$TARGET_PTR_LE" ]]; then
        echo "[+] Found pointer to k_slab_end at $addr"
        echo "[*] Dumping surrounding memory:"
        prev=$(dec_to_hex $((cur - 8)))
        kvm_prober readkvmem "$prev" 16 | xxd -r -p | hexdump -C
        break
    fi

    cur=$((cur + STEP))
done
