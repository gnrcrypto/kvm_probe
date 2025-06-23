#!/bin/bash

KERN_VER=$(uname -r)

### ===Install basic build tools===
apt update -y >/dev/null
apt install sudo make xxd gdb build-essential binutils tar -y >/dev/null || true
apt install -f -y >/dev/null

sleep 2
if [ ! -f "/root/vmlinux" ]; then
    echo "[*] Downloading latest kvmctf bundle for vmlinux..."
    wget -q https://storage.googleapis.com/kvmctf/latest.tar.gz
    tar -xzf latest.tar.gz
    mv /root/kvmctf-6.1.74/vmlinux/vmlinux /root
    echo "[+] vmlinux moved to /root"
else
    echo "[+] /root/vmlinux already exists, skipping download."
fi

sleep 2
wget -q https://debian.sipwise.com/debian-security/pool/main/l/linux/linux-headers-6.1.0-21-common_6.1.90-1_all.deb
wget -q https://debian.sipwise.com/debian-security/pool/main/l/linux/linux-headers-6.1.0-21-amd64_6.1.90-1_amd64.deb
dpkg -i linux-headers-6.1.0-21-common_6.1.90-1_all.deb || true
dpkg -i linux-headers-6.1.0-21-amd64_6.1.90-1_amd64.deb || true
apt install -f -y >/dev/null
apt-get --fix-missing install

### ===Install with verification===
sleep 2
echo "[*] Installing common headers"
dpkg -i "linux-headers-${KERN_VER%-*}-common_6.1.90-1_all.deb" || true

sleep 2
echo "[*] Installing architecture-specific headers"
dpkg -i "linux-headers-${KERN_VER%-*}_6.1.90-1_amd64.deb" || true

sleep 2
apt-get install linux-headers-6.1.0-21-common linux-image-${KERN_VER%-*} -y
apt-get build-dep linux-headers-6.1.0-21-common linux-image-${KERN_VER%-*} -y
apt-get --fix-missing install -y

### ===Verify installation===
sleep 2
echo "[*] Verifying header installation"
if [ -d "/lib/modules/$KERN_VER/build" ]; then
    echo "[+] Headers successfully installed at /lib/modules/$KERN_VER/build"
else
    echo "[!] Header installation failed - continuing with exploit anyway"
    echo "[!] Exploit doesn't require headers but they're nice to have for debugging"
fi

### ===System Configuration Checks===
sleep 2
echo "[*] Performing system configuration checks"

### ===Ensure kptr_restrict is disabled===
sleep 2
echo 0 | sudo tee /proc/sys/kernel/kptr_restrict >/dev/null
echo 0 | sudo tee /proc/sys/kernel/dmesg_restrict >/dev/null
echo "[+] Disabled kernel restrictions"

sleep 2
mkdir /tmp/kvm_probe
cp Makefile /tmp/kvm_probe
cp kvm_prober.c /tmp/kvm_probe
cp kvm_probe_drv.c /tmp/kvm_probe

sleep 2
cd /tmp/kvm_probe
make clean
make all
make install
cp kvm_prober /usr/bin
insmod *.ko
kvm_prober allocvqpage

echo -e "\n\033[1;36m[*] Ensuring environment is ready...\033[0m"

if grep -qw "nokaslr" /proc/cmdline; then
    echo "[+] KASLR is DISABLED (nokaslr in cmdline)"
else
    echo "[!] KASLR is ENABLED - attempting to disable for next boot..."
    # Add nokaslr to GRUB if not already present
    if ! grep -qw "nokaslr" /etc/default/grub; then
         sed -i 's/^GRUB_CMDLINE_LINUX=\"/GRUB_CMDLINE_LINUX=\"nokaslr /' /etc/default/grub
         update-grub
        echo "[+] 'nokaslr' added to GRUB. You must reboot for KASLR to be disabled."
        echo "[+] Reboot now? (y/N)"
        read answer
        if [[ "$answer" =~ ^[Yy]$ ]]; then
             reboot
        else
            echo "[!] KASLR will remain enabled until you reboot."
        fi
    else
        echo "[*] 'nokaslr' already in /etc/default/grub. Just reboot to disable KASLR."
    fi
fi
