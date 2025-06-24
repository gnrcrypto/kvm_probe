#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/device.h>
#include <linux/io.h>
#include <linux/slab.h>
#include <linux/errno.h>
#include <linux/gfp.h>
#include <linux/mm.h>
#include <linux/ktime.h>
#include <linux/types.h>
#include <linux/byteorder/generic.h>
#include <linux/kvm_para.h>
#include <linux/page-flags.h>
#include <linux/pagemap.h>
#include <linux/kdev_t.h>
#include <linux/err.h>
#include <linux/static_call.h>
#include <linux/pgtable.h>

#define DRIVER_NAME "kvm_probe_drv"
#define DEVICE_FILE_NAME "kvm_probe_dev"

#define VQ_PAGE_ORDER 0
#define VQ_PAGE_SIZE (1UL << (PAGE_SHIFT + VQ_PAGE_ORDER))
#define MAX_VQ_DESCS 256

static void *g_vq_virt_addr = NULL;
static dma_addr_t g_vq_phys_addr = 0;
static unsigned long g_vq_pfn = 0;

struct port_io_data {
    unsigned short port;
    unsigned int size;
    unsigned int value;
};

struct mmio_data {
    unsigned long phys_addr;
    unsigned long size;
    unsigned char __user *user_buffer;
    unsigned long single_value;
    unsigned int value_size;
};

struct vring_desc_kernel {
    __le64 addr;
    __le32 len;
    __le16 flags;
    __le16 next;
};

struct vq_desc_user_data {
    u16 index;
    u64 phys_addr;
    u32 len;
    u16 flags;
    u16 next_idx;
};

struct kvm_kernel_mem_read {
    unsigned long kernel_addr;
    unsigned long length;
    unsigned char __user *user_buf;
};

struct kvm_kernel_mem_write {
    unsigned long kernel_addr;
    unsigned long length;
    unsigned char __user *user_buf;
};

struct va_scan_data {
    unsigned long va;
    unsigned long size;
    unsigned char __user *user_buffer;
};

struct va_write_data {
    unsigned long va;
    unsigned long size;
    unsigned char __user *user_buffer;
};

struct hypercall_args {
    unsigned long nr;
    unsigned long arg0;
    unsigned long arg1;
    unsigned long arg2;
    unsigned long arg3;
};

// New PIO structures
struct kvm_probe_pio_val {
    __u16 port;
    __u8  size;
    __u32 pad;
    __u64 value;
};

struct kvm_probe_pio_buf {
    __u16 port;
    __u16 len;
    __u32 pad;
    __u64 buf_user;
};

#define IOCTL_READ_PORT          0x1001
#define IOCTL_WRITE_PORT         0x1002
#define IOCTL_READ_MMIO          0x1003
#define IOCTL_WRITE_MMIO         0x1004
#define IOCTL_ALLOC_VQ_PAGE      0x1005
#define IOCTL_FREE_VQ_PAGE       0x1006
#define IOCTL_WRITE_VQ_DESC      0x1007
#define IOCTL_TRIGGER_HYPERCALL  0x1008
#define IOCTL_READ_KERNEL_MEM    0x1009
#define IOCTL_WRITE_KERNEL_MEM   0x100A
#define IOCTL_VIRT_TO_PHYS       0x100F
#define IOCTL_SCAN_VA            0x1010
#define IOCTL_WRITE_VA           0x1011
#define IOCTL_HYPERCALL_ARGS     0x1012
// New IOCTLs
#define KVM_PROBE_IOCTL_WRITE_PIO_VAL  0x1013
#define KVM_PROBE_IOCTL_WRITE_PIO_BUF  0x1014

static long driver_ioctl(struct file *f, unsigned int cmd, unsigned long arg);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("KVM Probe Lab");
MODULE_DESCRIPTION("Kernel module for KVM exploitation");

static int major_num;
static struct class* driver_class = NULL;
static struct device* driver_device = NULL;

static long force_hypercall(void) {
    long ret;
    u64 start = ktime_get_ns();
    ret = kvm_hypercall0(KVM_HC_VAPIC_POLL_IRQ);
    u64 end = ktime_get_ns();
    printk(KERN_INFO "%s: HYPERCALL executed | latency=%llu ns | ret=%ld\n",
           DRIVER_NAME, end - start, ret);
    return ret;
}

static long do_hypercall(struct hypercall_args *args) {
    unsigned long nr = args->nr;
    unsigned long a0 = args->arg0;
    unsigned long a1 = args->arg1;
    unsigned long a2 = args->arg2;
    unsigned long a3 = args->arg3;
    
    long ret;
    u64 start = ktime_get_ns();
    
    if (a0 == 0 && a1 == 0 && a2 == 0 && a3 == 0) {
        ret = kvm_hypercall0(nr);
    } else if (a1 == 0 && a2 == 0 && a3 == 0) {
        ret = kvm_hypercall1(nr, a0);
    } else if (a2 == 0 && a3 == 0) {
        ret = kvm_hypercall2(nr, a0, a1);
    } else if (a3 == 0) {
        ret = kvm_hypercall3(nr, a0, a1, a2);
    } else {
        ret = kvm_hypercall4(nr, a0, a1, a2, a3);
    }
    
    u64 end = ktime_get_ns();
    printk(KERN_INFO "%s: HYPERCALL(%lu) executed | latency=%llu ns | ret=%ld\n",
           DRIVER_NAME, nr, end - start, ret);
    return ret;
}

static long driver_ioctl(struct file *f, unsigned int cmd, unsigned long arg) {
    struct port_io_data p_io_data_kernel;
    struct mmio_data m_io_data_kernel;
    void __iomem *mapped_addr = NULL;
    unsigned long len_to_copy;
    unsigned char *k_mmio_buffer = NULL;
    
    printk(KERN_CRIT "%s: IOCTL ENTRY! cmd=0x%x, arg=0x%lx. ktime=%llu\n",
           DRIVER_NAME, cmd, arg, ktime_get_ns());
    
    switch (cmd) {
        case IOCTL_READ_PORT:
            if (copy_from_user(&p_io_data_kernel, (struct port_io_data __user *)arg, sizeof(p_io_data_kernel))) {
                printk(KERN_ERR "%s: READ_PORT: copy_from_user failed. ktime=%llu\n", DRIVER_NAME, ktime_get_ns());
                return -EFAULT;
            }
            printk(KERN_INFO "%s: IOCTL_READ_PORT: port=0x%hx, req_size=%u. ktime=%llu\n",
                   DRIVER_NAME, p_io_data_kernel.port, p_io_data_kernel.size, ktime_get_ns());
            if (p_io_data_kernel.size != 1 && p_io_data_kernel.size != 2 && p_io_data_kernel.size != 4) {
                printk(KERN_WARNING "%s: READ_PORT: Invalid size: %u. ktime=%llu\n", DRIVER_NAME, p_io_data_kernel.size, ktime_get_ns());
                return -EINVAL;
            }
            switch (p_io_data_kernel.size) {
                case 1: p_io_data_kernel.value = inb(p_io_data_kernel.port); break;
                case 2: p_io_data_kernel.value = inw(p_io_data_kernel.port); break;
                case 4: p_io_data_kernel.value = inl(p_io_data_kernel.port); break;
            }
            printk(KERN_INFO "%s: IOCTL_READ_PORT: value_read=0x%x from port 0x%hx. ktime=%llu\n",
                   DRIVER_NAME, p_io_data_kernel.value, p_io_data_kernel.port, ktime_get_ns());
            if (copy_to_user((struct port_io_data __user *)arg, &p_io_data_kernel, sizeof(p_io_data_kernel))) {
                printk(KERN_ERR "%s: READ_PORT: copy_to_user failed. ktime=%llu\n", DRIVER_NAME, ktime_get_ns());
                return -EFAULT;
            }
            force_hypercall();
            break;
            
                case IOCTL_WRITE_PORT:
                    if (copy_from_user(&p_io_data_kernel, (struct port_io_data __user *)arg, sizeof(p_io_data_kernel))) {
                        printk(KERN_ERR "%s: WRITE_PORT: copy_from_user failed. ktime=%llu\n", DRIVER_NAME, ktime_get_ns());
                        return -EFAULT;
                    }
                    printk(KERN_INFO "%s: IOCTL_WRITE_PORT: port=0x%hx, value_to_write=0x%x, req_size=%u. ktime=%llu\n",
                           DRIVER_NAME, p_io_data_kernel.port, p_io_data_kernel.value, p_io_data_kernel.size, ktime_get_ns());
                    if (p_io_data_kernel.size != 1 && p_io_data_kernel.size != 2 && p_io_data_kernel.size != 4) {
                        printk(KERN_WARNING "%s: WRITE_PORT: Invalid size: %u. ktime=%llu\n", DRIVER_NAME, p_io_data_kernel.size, ktime_get_ns());
                        return -EINVAL;
                    }
                    switch (p_io_data_kernel.size) {
                        case 1: outb((u8)p_io_data_kernel.value, p_io_data_kernel.port); break;
                        case 2: outw((u16)p_io_data_kernel.value, p_io_data_kernel.port); break;
                        case 4: outl((u32)p_io_data_kernel.value, p_io_data_kernel.port); break;
                    }
                    printk(KERN_INFO "%s: IOCTL_WRITE_PORT: Write to port 0x%hx completed. ktime=%llu\n",
                           DRIVER_NAME, p_io_data_kernel.port, ktime_get_ns());
                    force_hypercall();
                    break;
                    
                        case IOCTL_READ_MMIO: {
                            struct mmio_data data;
                            if (copy_from_user(&data, (void __user *)arg, sizeof(data))) {
                                printk(KERN_ERR "%s: IOCTL_READ_MMIO: copy_from_user failed\n", DRIVER_NAME);
                                return -EFAULT;
                            }
                            printk(KERN_INFO "%s: IOCTL_READ_MMIO: Reading phys_addr=0x%lx, size=0x%lx, user_buffer=%px\n",
                                   DRIVER_NAME, data.phys_addr, data.size, data.user_buffer);
                            void __iomem *mmio = ioremap(data.phys_addr, data.size);
                            if (!mmio) {
                                printk(KERN_ERR "%s: IOCTL_READ_MMIO: ioremap failed\n", DRIVER_NAME);
                                return -EFAULT;
                            }
                            void *kbuf = kmalloc(data.size, GFP_KERNEL);
                            if (!kbuf) {
                                iounmap(mmio);
                                return -ENOMEM;
                            }
                            memcpy_fromio(kbuf, mmio, data.size);
                            if (copy_to_user(data.user_buffer, kbuf, data.size)) {
                                kfree(kbuf);
                                iounmap(mmio);
                                return -EFAULT;
                            }
                            printk(KERN_INFO "%s: IOCTL_READ_MMIO: Read %lu bytes from 0x%lx OK\n", DRIVER_NAME, data.size, data.phys_addr);
                            kfree(kbuf);
                            iounmap(mmio);
                            force_hypercall();
                            return 0;
                        }
                        
                        case IOCTL_WRITE_MMIO: {
                            if (copy_from_user(&m_io_data_kernel, (struct mmio_data __user *)arg, sizeof(m_io_data_kernel))) {
                                printk(KERN_ERR "%s: IOCTL_WRITE_MMIO: copy_from_user failed\n", DRIVER_NAME);
                                return -EFAULT;
                            }
                            unsigned long map_size = m_io_data_kernel.size > 0 ? m_io_data_kernel.size : m_io_data_kernel.value_size;
                            if (map_size == 0) {
                                printk(KERN_ERR "%s: IOCTL_WRITE_MMIO: Map size is zero\n", DRIVER_NAME);
                                return -EINVAL;
                            }
                            printk(KERN_INFO "%s: IOCTL_WRITE_MMIO: Writing phys_addr=0x%lx, map_size=%lu, user_buffer=%px\n",
                                   DRIVER_NAME, m_io_data_kernel.phys_addr, map_size, m_io_data_kernel.user_buffer);
                            mapped_addr = ioremap(m_io_data_kernel.phys_addr, map_size);
                            if (!mapped_addr) {
                                printk(KERN_ERR "%s: IOCTL_WRITE_MMIO: ioremap failed\n", DRIVER_NAME);
                                return -ENOMEM;
                            }
                            if (m_io_data_kernel.size > 0) {
                                if (!m_io_data_kernel.user_buffer) {
                                    printk(KERN_ERR "%s: IOCTL_WRITE_MMIO: User buffer NULL\n", DRIVER_NAME);
                                    iounmap(mapped_addr);
                                    return -EFAULT;
                                }
                                k_mmio_buffer = kmalloc(m_io_data_kernel.size, GFP_KERNEL);
                                if (!k_mmio_buffer) {
                                    iounmap(mapped_addr);
                                    return -ENOMEM;
                                }
                                if (copy_from_user(k_mmio_buffer, m_io_data_kernel.user_buffer, m_io_data_kernel.size)) {
                                    kfree(k_mmio_buffer);
                                    iounmap(mapped_addr);
                                    return -EFAULT;
                                }
                                for (len_to_copy = 0; len_to_copy < m_io_data_kernel.size; ++len_to_copy) {
                                    writeb(k_mmio_buffer[len_to_copy], mapped_addr + len_to_copy);
                                }
                                printk(KERN_INFO "%s: IOCTL_WRITE_MMIO: Wrote %lu bytes to 0x%lx OK\n", DRIVER_NAME, m_io_data_kernel.size, m_io_data_kernel.phys_addr);
                                kfree(k_mmio_buffer);
                            } else {
                                switch(m_io_data_kernel.value_size) {
                                    case 1: writeb((u8)m_io_data_kernel.single_value, mapped_addr); break;
                                    case 2: writew((u16)m_io_data_kernel.single_value, mapped_addr); break;
                                    case 4: writel((u32)m_io_data_kernel.single_value, mapped_addr); break;
                                    case 8: writeq(m_io_data_kernel.single_value, mapped_addr); break;
                                    default:
                                        printk(KERN_ERR "%s: IOCTL_WRITE_MMIO: Invalid value_size %u\n", DRIVER_NAME, m_io_data_kernel.value_size);
                                        iounmap(mapped_addr);
                                        return -EINVAL;
                                }
                                printk(KERN_INFO "%s: IOCTL_WRITE_MMIO: Wrote %u bytes to 0x%lx OK\n", DRIVER_NAME, m_io_data_kernel.value_size, m_io_data_kernel.phys_addr);
                            }
                            iounmap(mapped_addr);
                            force_hypercall();
                            return 0;
                        }
                        
                                    case IOCTL_READ_KERNEL_MEM: {
                                        struct kvm_kernel_mem_read req;
                                        if (copy_from_user(&req, (struct kvm_kernel_mem_read __user *)arg, sizeof(req))) {
                                            printk(KERN_ERR "%s: READ_KERNEL_MEM: copy_from_user failed\n", DRIVER_NAME);
                                            return -EFAULT;
                                        }
                                        if (!req.kernel_addr || !req.length || !req.user_buf) {
                                            printk(KERN_ERR "%s: READ_KERNEL_MEM: Null arg\n", DRIVER_NAME);
                                            return -EINVAL;
                                        }
                                        if (copy_to_user(req.user_buf, (void *)req.kernel_addr, req.length)) {
                                            printk(KERN_ERR "%s: READ_KERNEL_MEM: copy_to_user failed for kernel_addr=0x%lx\n", DRIVER_NAME, req.kernel_addr);
                                            return -EFAULT;
                                        }
                                        printk(KERN_CRIT "%s: READ_KERNEL_MEM: read OK for 0x%lx\n", DRIVER_NAME, req.kernel_addr);
                                        force_hypercall();
                                        break;
                                    }
                                    
                                    case IOCTL_WRITE_KERNEL_MEM: {
                                        struct kvm_kernel_mem_write req;
                                        if (copy_from_user(&req, (struct kvm_kernel_mem_write __user *)arg, sizeof(req))) {
                                            printk(KERN_ERR "%s: WRITE_KERNEL_MEM: copy_from_user failed\n", DRIVER_NAME);
                                            return -EFAULT;
                                        }
                                        if (!req.kernel_addr || !req.length || !req.user_buf) {
                                            printk(KERN_ERR "%s: WRITE_KERNEL_MEM: Null arg\n", DRIVER_NAME);
                                            return -EINVAL;
                                        }
                                        void *tmp = kmalloc(req.length, GFP_KERNEL);
                                        if (!tmp) return -ENOMEM;
                                        if (copy_from_user(tmp, req.user_buf, req.length)) {
                                            kfree(tmp);
                                            return -EFAULT;
                                        }
                                        memcpy((void *)req.kernel_addr, tmp, req.length);
                                        kfree(tmp);
                                        printk(KERN_CRIT "%s: WRITE_KERNEL_MEM: wrote %lu bytes to 0x%lx\n", DRIVER_NAME, req.length, req.kernel_addr);
                                        force_hypercall();
                                        break;
                                    }
                                    
                                    case IOCTL_ALLOC_VQ_PAGE: {
                                        struct page *vq_page_ptr;
                                        unsigned long pfn_to_user;
                                        if (g_vq_virt_addr) {
                                            printk(KERN_INFO "%s: ALLOC_VQ_PAGE: Freeing previous VQ page (virt: %p, phys: 0x%llx). ktime=%llu\n",
                                                   DRIVER_NAME, g_vq_virt_addr, (unsigned long long)g_vq_phys_addr, ktime_get_ns());
                                            free_pages((unsigned long)g_vq_virt_addr, VQ_PAGE_ORDER);
                                            g_vq_virt_addr = NULL;
                                            g_vq_phys_addr = 0;
                                            g_vq_pfn = 0;
                                        }
                                        vq_page_ptr = alloc_pages(GFP_KERNEL | __GFP_ZERO | __GFP_HIGHMEM, VQ_PAGE_ORDER);
                                        if (!vq_page_ptr) {
                                            printk(KERN_ERR "%s: ALLOC_VQ_PAGE: Failed to allocate VQ page. ktime=%llu\n", DRIVER_NAME, ktime_get_ns());
                                            return -ENOMEM;
                                        }
                                        g_vq_virt_addr = page_address(vq_page_ptr);
                                        g_vq_phys_addr = page_to_phys(vq_page_ptr);
                                        g_vq_pfn = PFN_DOWN(g_vq_phys_addr);
                                        pfn_to_user = g_vq_pfn;
                                        printk(KERN_INFO "%s: ALLOC_VQ_PAGE: Allocated VQ page: virt=%p, phys=0x%llx, pfn=0x%lx, size=%lu. ktime=%llu\n",
                                               DRIVER_NAME, g_vq_virt_addr, (unsigned long long)g_vq_phys_addr, g_vq_pfn, VQ_PAGE_SIZE, ktime_get_ns());
                                        if (copy_to_user((unsigned long __user *)arg, &pfn_to_user, sizeof(pfn_to_user))) {
                                            printk(KERN_ERR "%s: ALLOC_VQ_PAGE: copy_to_user failed for PFN. ktime=%llu\n", DRIVER_NAME, ktime_get_ns());
                                            free_pages((unsigned long)g_vq_virt_addr, VQ_PAGE_ORDER);
                                            g_vq_virt_addr = NULL;
                                            g_vq_phys_addr = 0;
                                            g_vq_pfn = 0;
                                            return -EFAULT;
                                        }
                                        force_hypercall();
                                        break;
                                    }
                                    
                                    case IOCTL_FREE_VQ_PAGE: {
                                        printk(KERN_INFO "%s: IOCTL_FREE_VQ_PAGE. ktime=%llu\n", DRIVER_NAME, ktime_get_ns());
                                        if (g_vq_virt_addr) {
                                            printk(KERN_INFO "%s: FREE_VQ_PAGE: Freeing VQ page (virt: %p, phys: 0x%llx). ktime=%llu\n",
                                                   DRIVER_NAME, g_vq_virt_addr, (unsigned long long)g_vq_phys_addr, ktime_get_ns());
                                            free_pages((unsigned long)g_vq_virt_addr, VQ_PAGE_ORDER);
                                            g_vq_virt_addr = NULL;
                                            g_vq_phys_addr = 0;
                                            g_vq_pfn = 0;
                                        } else {
                                            printk(KERN_INFO "%s: FREE_VQ_PAGE: No VQ page currently allocated. ktime=%llu\n", DRIVER_NAME, ktime_get_ns());
                                        }
                                        force_hypercall();
                                        break;
                                    }
                                    
                                    case IOCTL_WRITE_VQ_DESC: {
                                        struct vq_desc_user_data user_desc_data_kernel;
                                        struct vring_desc_kernel *kernel_desc_ptr_local;
                                        unsigned int max_descs_in_page_local;
                                        printk(KERN_INFO "%s: IOCTL_WRITE_VQ_DESC received. ktime=%llu\n", DRIVER_NAME, ktime_get_ns());
                                        if (!g_vq_virt_addr) {
                                            printk(KERN_ERR "%s: WRITE_VQ_DESC: VQ page not allocated. Call ALLOC_VQ_PAGE first.\n", DRIVER_NAME);
                                            return -ENXIO;
                                        }
                                        if (copy_from_user(&user_desc_data_kernel, (struct vq_desc_user_data __user *)arg, sizeof(user_desc_data_kernel))) {
                                            return -EFAULT;
                                        }
                                        max_descs_in_page_local = VQ_PAGE_SIZE / sizeof(struct vring_desc_kernel);
                                        if (user_desc_data_kernel.index >= max_descs_in_page_local) {
                                            printk(KERN_ERR "%s: WRITE_VQ_DESC: Descriptor index %u out of bounds (max %u)\n",
                                                   DRIVER_NAME, user_desc_data_kernel.index, max_descs_in_page_local - 1);
                                            return -EINVAL;
                                        }
                                        kernel_desc_ptr_local = (struct vring_desc_kernel *)g_vq_virt_addr + user_desc_data_kernel.index;
                                        kernel_desc_ptr_local->addr = cpu_to_le64(user_desc_data_kernel.phys_addr);
                                        kernel_desc_ptr_local->len = cpu_to_le32(user_desc_data_kernel.len);
                                        kernel_desc_ptr_local->flags = cpu_to_le16(user_desc_data_kernel.flags);
                                        kernel_desc_ptr_local->next = cpu_to_le16(user_desc_data_kernel.next_idx);
                                        printk(KERN_INFO "%s: Wrote VQ desc at index %u: GPA=0x%llx, len=%u, flags=0x%hx, next=%hu. ktime=%llu\n",
                                               DRIVER_NAME, user_desc_data_kernel.index, user_desc_data_kernel.phys_addr,
                                               user_desc_data_kernel.len, user_desc_data_kernel.flags, user_desc_data_kernel.next_idx, ktime_get_ns());
                                        force_hypercall();
                                        break;
                                    }
                                    
                                    case IOCTL_TRIGGER_HYPERCALL: {
                                        printk(KERN_INFO "%s: DIRECT HYPERCALL TRIGGER. ktime=%llu\n", DRIVER_NAME, ktime_get_ns());
                                        long ret = force_hypercall();
                                        if (copy_to_user((long __user *)arg, &ret, sizeof(ret))) {
                                            printk(KERN_ERR "%s: TRIGGER_HYPERCALL: copy_to_user failed\n", DRIVER_NAME);
                                            return -EFAULT;
                                        }
                                        break;
                                    }
                                    
                                    case IOCTL_SCAN_VA: {
                                        struct va_scan_data va_req;
                                        if (copy_from_user(&va_req, (struct va_scan_data __user *)arg, sizeof(va_req))) {
                                            printk(KERN_ERR "%s: IOCTL_SCAN_VA: copy_from_user failed\n", DRIVER_NAME);
                                            return -EFAULT;
                                        }
                                        if (!va_req.va || !va_req.size || !va_req.user_buffer) {
                                            printk(KERN_ERR "%s: IOCTL_SCAN_VA: Null arg(s)\n", DRIVER_NAME);
                                            return -EINVAL;
                                        }
                                        void *src = (void *)va_req.va;
                                        unsigned char *tmp = kmalloc(va_req.size, GFP_KERNEL);
                                        if (!tmp) {
                                            printk(KERN_ERR "%s: IOCTL_SCAN_VA: kmalloc failed\n", DRIVER_NAME);
                                            return -ENOMEM;
                                        }
                                        memcpy(tmp, src, va_req.size);
                                        if (copy_to_user(va_req.user_buffer, tmp, va_req.size)) {
                                            kfree(tmp);
                                            printk(KERN_ERR "%s: IOCTL_SCAN_VA: copy_to_user failed\n", DRIVER_NAME);
                                            return -EFAULT;
                                        }
                                        kfree(tmp);
                                        printk(KERN_CRIT "%s: IOCTL_SCAN_VA: dumped 0x%lx bytes from VA 0x%lx\n",
                                               DRIVER_NAME, va_req.size, va_req.va);
                                        force_hypercall();
                                        return 0;
                                    }
                                    
                                    case IOCTL_WRITE_VA: {
                                        struct va_write_data wa_req;
                                        if (copy_from_user(&wa_req, (struct va_write_data __user *)arg, sizeof(wa_req))) {
                                            printk(KERN_ERR "%s: IOCTL_WRITE_VA: copy_from_user failed\n", DRIVER_NAME);
                                            return -EFAULT;
                                        }
                                        if (!wa_req.va || !wa_req.size || !wa_req.user_buffer) {
                                            printk(KERN_ERR "%s: IOCTL_WRITE_VA: Null arg(s)\n", DRIVER_NAME);
                                            return -EINVAL;
                                        }
                                        unsigned char *tmp = kmalloc(wa_req.size, GFP_KERNEL);
                                        if (!tmp) {
                                            printk(KERN_ERR "%s: IOCTL_WRITE_VA: kmalloc failed\n", DRIVER_NAME);
                                            return -ENOMEM;
                                        }
                                        if (copy_from_user(tmp, wa_req.user_buffer, wa_req.size)) {
                                            kfree(tmp);
                                            printk(KERN_ERR "%s: IOCTL_WRITE_VA: copy_from_user failed (user buf)\n", DRIVER_NAME);
                                            return -EFAULT;
                                        }
                                        memcpy((void *)wa_req.va, tmp, wa_req.size);
                                        kfree(tmp);
                                        printk(KERN_CRIT "%s: IOCTL_WRITE_VA: wrote 0x%lx bytes to VA 0x%lx\n",
                                               DRIVER_NAME, wa_req.size, wa_req.va);
                                        force_hypercall();
                                        return 0;
                                    }
                                    
                                    case IOCTL_HYPERCALL_ARGS: {
                                        struct hypercall_args args;
                                        if (copy_from_user(&args, (void __user *)arg, sizeof(args))) {
                                            printk(KERN_ERR "%s: HYPERCALL_ARGS: copy_from_user failed\n", DRIVER_NAME);
                                            return -EFAULT;
                                        }
                                        long ret = do_hypercall(&args);
                                        if (copy_to_user((void __user *)arg, &ret, sizeof(ret))) {
                                            printk(KERN_ERR "%s: HYPERCALL_ARGS: copy_to_user failed\n", DRIVER_NAME);
                                            return -EFAULT;
                                        }
                                        break;
                                    }
                                    
                                    case IOCTL_VIRT_TO_PHYS: {
                                        printk(KERN_INFO "%s: IOCTL_VIRT_TO_PHYS called.\n", DRIVER_NAME);
                                        
                                        unsigned long va, pa;
                                        if (copy_from_user(&va, (void __user *)arg, sizeof(va)))
                                            return -EFAULT;
                                        if (!va)
                                            return -EINVAL;
                                        
                                        pa = virt_to_phys((void *)va);
                                        return copy_to_user((void __user *)arg, &pa, sizeof(pa)) ? -EFAULT : 0;
                                    }
                                    
                                    // New PIO operations
                                    case KVM_PROBE_IOCTL_WRITE_PIO_VAL: {
                                        struct kvm_probe_pio_val p;
                                        if (copy_from_user(&p, (void __user *)arg, sizeof(p))) {
                                            printk(KERN_ERR "%s: WRITE_PIO_VAL: copy_from_user failed\n", DRIVER_NAME);
                                            return -EFAULT;
                                        }
                                        if (p.size != 1 && p.size != 2 && p.size != 4) {
                                            printk(KERN_ERR "%s: WRITE_PIO_VAL: Invalid size %u\n", DRIVER_NAME, p.size);
                                            return -EINVAL;
                                        }
                                        switch (p.size) {
                                            case 1: outb((u8)p.value, p.port); break;
                                            case 2: outw((u16)p.value, p.port); break;
                                            case 4: outl((u32)p.value, p.port); break;
                                        }
                                        printk(KERN_INFO "%s: Wrote PIO val 0x%llx to port 0x%hx (size %u)\n",
                                               DRIVER_NAME, p.value, p.port, p.size);
                                        force_hypercall();
                                        return 0;
                                    }
                                    
                                            case KVM_PROBE_IOCTL_WRITE_PIO_BUF: {
                                                struct kvm_probe_pio_buf hdr;
                                                if (copy_from_user(&hdr, (void __user *)arg, sizeof(hdr))) {
                                                    printk(KERN_ERR "%s: WRITE_PIO_BUF: copy_from_user failed\n", DRIVER_NAME);
                                                    return -EFAULT;
                                                }
                                                if (hdr.len == 0) return 0;
                                                if (hdr.len > 4096) {
                                                    printk(KERN_ERR "%s: WRITE_PIO_BUF: Buffer too large (%u)\n", DRIVER_NAME, hdr.len);
                                                    return -EINVAL;
                                                }
                                                u8 stack_buf[4096];
                                                if (copy_from_user(stack_buf, (void __user *)(uintptr_t)hdr.buf_user, hdr.len)) {
                                                    printk(KERN_ERR "%s: WRITE_PIO_BUF: buffer copy_from_user failed\n", DRIVER_NAME);
                                                    return -EFAULT;
                                                }
                                                outsb(hdr.port, stack_buf, hdr.len);
                                                printk(KERN_INFO "%s: Wrote PIO buf len %u to port 0x%hx\n", DRIVER_NAME, hdr.len, hdr.port);
                                                force_hypercall();
                                                return 0;
                                            }
                                            
                                            default:
                                                printk(KERN_ERR "%s: Unknown IOCTL command: 0x%x\n", DRIVER_NAME, cmd);
                                                return -EINVAL;
    }
    return 0;
}

static const struct file_operations fops = {
    .owner = THIS_MODULE,
    .unlocked_ioctl = driver_ioctl,
};

static int __init mod_init(void) {
    printk(KERN_INFO "%s: Initializing Enhanced KVM Probe Module.\n", DRIVER_NAME);
    major_num = register_chrdev(0, DEVICE_FILE_NAME, &fops);
    if (major_num < 0) {
        printk(KERN_ERR "%s: register_chrdev failed: %d\n", DRIVER_NAME, major_num);
        return major_num;
    }
    driver_class = class_create(THIS_MODULE, DRIVER_NAME);
    if (IS_ERR(driver_class)) {
        unregister_chrdev(major_num, DEVICE_FILE_NAME);
        printk(KERN_ERR "%s: class_create failed\n", DRIVER_NAME);
        return PTR_ERR(driver_class);
    }
    driver_device = device_create(driver_class, NULL, MKDEV(major_num, 0), NULL, DEVICE_FILE_NAME);
    if (IS_ERR(driver_device)) {
        class_destroy(driver_class);
        unregister_chrdev(major_num, DEVICE_FILE_NAME);
        printk(KERN_ERR "%s: device_create failed\n", DRIVER_NAME);
        return PTR_ERR(driver_device);
    }
    g_vq_virt_addr = NULL;
    g_vq_phys_addr = 0;
    g_vq_pfn = 0;
    printk(KERN_INFO "%s: Module loaded. Device /dev/%s created with major %d.\n", DRIVER_NAME, DEVICE_FILE_NAME, major_num);
    return 0;
}

static void __exit mod_exit(void) {
    printk(KERN_INFO "%s: Unloading KVM Probe Module.\n", DRIVER_NAME);
    if (g_vq_virt_addr) {
        printk(KERN_INFO "%s: mod_exit: Freeing VQ page (virt: %p, phys: 0x%llx).\n",
               DRIVER_NAME, g_vq_virt_addr, (unsigned long long)g_vq_phys_addr);
        free_pages((unsigned long)g_vq_virt_addr, VQ_PAGE_ORDER);
        g_vq_virt_addr = NULL;
        g_vq_phys_addr = 0;
        g_vq_pfn = 0;
    }
    if (driver_device) {
        device_destroy(driver_class, MKDEV(major_num, 0));
    }
    if (driver_class) {
        class_unregister(driver_class);
        class_destroy(driver_class);
    }
    if (major_num >= 0) {
        unregister_chrdev(major_num, DEVICE_FILE_NAME);
    }
    printk(KERN_INFO "%s: Module unloaded.\n", DRIVER_NAME);
}

module_init(mod_init);
module_exit(mod_exit);
