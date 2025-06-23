#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <sys/ioctl.h>
#include <stdint.h>
#include <errno.h>

#define DEVICE "/dev/kvm_probe_dev"

#define IOCTL_WRITE_PORT        0x1003
#define IOCTL_READ_MMIO         0x1008
#define IOCTL_WRITE_MMIO        0x1009
#define IOCTL_SCAN_VA           0x100A
#define IOCTL_WRITE_VA          0x100B
#define IOCTL_SCAN_PA           0x100C  // New command
// Keep these unchanged
#define IOCTL_ALLOC_VQ_PAGE     0x1005
#define IOCTL_FREE_VQ_PAGE      0x1006
#define IOCTL_WRITE_VQ_DESC     0x1007
#define IOCTL_TRIGGER_HYPERCALL 0x1010
#define IOCTL_HYPERCALL_ARGS    0x1012

struct kvm_kernel_mem_rw {
    uint64_t kernel_addr;
    uint64_t length;
    uint8_t *user_buf;
};

struct port_io_data {
    uint16_t port;
    uint32_t size;
    uint32_t value;
};

struct mmio_data {
    uint64_t phys_addr;
    uint64_t size;
    uint8_t *user_buffer;
};

struct va_data {
    uint64_t va;
    uint64_t size;
    uint8_t *user_buffer;
};

int kernel_mem_op(int fd, uint64_t addr, uint64_t len, uint8_t *buf, int op) {
    struct kvm_kernel_mem_rw req = { .kernel_addr = addr, .length = len, .user_buf = buf };
    return ioctl(fd, op, &req);
}

int port_io(int fd, uint16_t port, uint32_t size, uint32_t *value, int op) {
    struct port_io_data req = { .port = port, .size = size, .value = *value };
    int ret = ioctl(fd, op, &req);
    *value = req.value;
    return ret;
}

int mmio_op(int fd, uint64_t addr, uint64_t len, uint8_t *buf, int op) {
    struct mmio_data req = { .phys_addr = addr, .size = len, .user_buffer = buf };
    return ioctl(fd, op, &req);
}

int va_op(int fd, uint64_t addr, uint64_t len, uint8_t *buf, int op) {
    struct va_data req = { .va = addr, .size = len, .user_buffer = buf };
    return ioctl(fd, op, &req);
}

int trigger_hypercall(int fd) {
    long ret;
    return ioctl(fd, IOCTL_TRIGGER_HYPERCALL, &ret);
}

void usage(const char *prog) {
    printf("Usage: %s [options]\n", prog);
    printf("  -k [r|w] addr size [value]\tKernel memory read/write (0x1009/0x100A)\n");
    printf("     Example: %s -k r 0xffffffff826279a8 8\n", prog);
    printf("  -p [r|w] port size [value]\tPort IO read/write (0x1001/0x1002)\n");
    printf("     Example: %s -p w 0x3f8 1 0xff\n", prog);
    printf("  -m [r|w] addr size [value]\tMMIO read/write (0x1003/0x1004)\n");
    printf("     Example: %s -m r 0x1000 16\n", prog);
    printf("  -v [r|w] addr size [value]\tVA memory read/write (0x1010/0x1011)\n");
    printf("     Example: %s -v w 0x7fffffffe000 8 0xdeadbeef\n", prog);
    printf("  -h\t\t\tTrigger hypercall (0x1008)\n");
    printf("     Example: %s -h\n", prog);
}

int main(int argc, char *argv[]) {
    int fd, opt;

    fd = open(DEVICE, O_RDWR);
    if (fd < 0) { perror("open"); return -1; }

    while ((opt = getopt(argc, argv, "k:p:m:v:h")) != -1) {
        uint64_t addr, len, value;
        uint8_t buffer[256];

        switch (opt) {
            case 'k':
            case 'p':
            case 'm':
            case 'v':
                if (optind + 1 >= argc) { usage(argv[0]); close(fd); return -1; }

                addr = strtoull(argv[optind], NULL, 16);
                len = strtoull(argv[optind + 1], NULL, 10);
                if (len > sizeof(buffer)) len = sizeof(buffer);

                if (optarg[0] == 'r') {
                    int res = -1;
                    if (opt == 'k') res = kernel_mem_op(fd, addr, len, buffer, IOCTL_READ_KERNEL_MEM);
                    else if (opt == 'p') res = port_io(fd, addr, len, (uint32_t *)buffer, IOCTL_READ_PORT);
                    else if (opt == 'm') res = mmio_op(fd, addr, len, buffer, IOCTL_READ_MMIO);
                    else if (opt == 'v') res = va_op(fd, addr, len, buffer, IOCTL_SCAN_VA);

                    if (res == 0) {
                        printf("Read successful:\n");
                        for (uint64_t i = 0; i < len; i++) printf("%02x ", buffer[i]);
                        printf("\n");
                    } else perror("Read failed");

                } else if (optarg[0] == 'w') {
                    if (optind + 2 >= argc) { usage(argv[0]); close(fd); return -1; }
                    value = strtoull(argv[optind + 2], NULL, 16);
                    memcpy(buffer, &value, sizeof(value));

                    if (opt == 'k') kernel_mem_op(fd, addr, sizeof(value), buffer, IOCTL_WRITE_KERNEL_MEM);
                    else if (opt == 'p') port_io(fd, addr, len, (uint32_t *)&value, IOCTL_WRITE_PORT);
                    else if (opt == 'm') mmio_op(fd, addr, sizeof(value), buffer, IOCTL_WRITE_MMIO);
                    else if (opt == 'v') va_op(fd, addr, sizeof(value), buffer, IOCTL_WRITE_VA);

                    printf("Write operation completed.\n");
                } else {
                    usage(argv[0]); close(fd); return -1;
                }
                break;

            case 'h':
                if (trigger_hypercall(fd) == 0) printf("Hypercall triggered successfully.\n");
                else perror("Hypercall failed");
                break;

            default:
                usage(argv[0]); close(fd); return -1;
        }
    }
    close(fd);
    return 0;
}
