---
layout: article
title:  "Linux Kernel调试环境搭建"
tags: pwn
---

_version_: 1.3

Linux Kernel + Busybox + Qemu

此文记录我的Linux Kernel调试环境搭建过程。
<!--more-->
参考于[blog](http://pwn.beers4flags.fr/exploit/kernel-cve-2017-5123/)。

## 1. 新建工作目录，如CVE-2017-5123

```
$ mkdir CVE-2017-5123
$ cd CVE-2017-5123
```

## 2. 编译kernel

```
$ wget https://cdn.kernel.org/pub/linux/kernel/v4.x/linux-4.13.tar.xz
$ tar xf linux-4.13.tar.xz
$ cd linux-4.13
$ make defconfig
$ make menuconfig
$ vim .config
```

需要在.config中添加如下编译选项：

```
# for the 9pnet share we need 9p and virtio:

CONFIG_NET_9P=y
CONFIG_NET_9P_VIRTIO=m
CONFIG_NET_9P_DEBUG=y
CONFIG_9P_FS=y
CONFIG_9P_FS_POSIX_ACL=y
CONFIG_9P_FS_SECURITY=y
CONFIG_BLK_MQ_VIRTIO=y
CONFIG_NET_9P_VIRTIO=m
CONFIG_VIRTIO_NET=m
CONFIG_VIRTIO=m
CONFIG_VIRTIO_PCI=m
CONFIG_VIRTIO_PCI_LEGACY=y
CONFIG_VIRTIO_MMIO=m
CONFIG_CRYPTO_DEV_VIRTIO=m

# for debug:
CONFIG_DEBUG_INFO=y
# We can also add:
CONFIG_GDB_SCRIPTS=y #for using all gdb-script who come with the kernel
```

关于[9PNET share](https://wiki.qemu.org/Documentation/9psetup)

改好配置文件后，编译内核：

```
$ make -j4 bzImage
$ cd ..
```

## 3. 使用busybox创建initramfs 

```
$ wget https://busybox.net/downloads/busybox-1.28.1.tar.bz2
$ tar xf busybox-1.28.1.tar.bz2
$ cd busybox-1.28.1
$ make defconfig
$ make -j4 CFLAGS=-static install
```

这里务必要添加**-static**选项确保静态编译无动态库依赖。

这样，我们需要的initramfs根目录就在\_install目录下了：

```
$ ls _install
bin  linuxrc  sbin  usr
```

将_install目录移到initramfs\_root目录：

```
$ mv _install ../initramfs_root
```

为initramfs\_root根目录添加文件夹：

```
$ cd ../initramfs_root
$ mkdir etc dev proc sys home root home/vigi
```

创建etc/passwd文件：

```
$ vim etc/passwd
$ cat etc/passwd
root:x:0:0:root:/root:/bin/sh
vigi:x:1000:1000:user:/home/vigi:/bin/sh
```

创建etc/init.d/rcS文件并给予运行权限：

```
$ mkdir -p etc/init.d
$ echo 'for i in $(seq 1 9); do mknod /dev/tty$i c 4 1; done' > etc/init.d/rcS
$ chmod +x etc/init.d/rcS
```

创建init文件并给予运行权限：

```
$ vim init
$ chmod +x init
$ cat init
#!/bin/sh

echo "IF9fICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgLl9fICAgICAgICAgICAgICAgICAgICAgICAgIA0KfCAgfCBfXyBfX19fX19fX19fXyAgX19fXyAgIF9fX18gfCAgfCAgIF9fX19fX19fICBfICBfX19fX18gIA0KfCAgfC8gLy8gX18gXF8gIF9fIFwvICAgIFxfLyBfXyBcfCAgfCAgIFxfX19fIFwgXC8gXC8gLyAgICBcIA0KfCAgICA8XCAgX19fL3wgIHwgXC8gICB8ICBcICBfX18vfCAgfF9fIHwgIHxfPiA+ICAgICAvICAgfCAgXA0KfF9ffF8gXFxfX18gID5fX3wgIHxfX198ICAvXF9fXyAgPl9fX18vIHwgICBfXy8gXC9cXy98X19ffCAgLw0KICAgICBcLyAgICBcLyAgICAgICAgICAgXC8gICAgIFwvICAgICAgIHxfX3wgICAgICAgICAgICAgIFwvIA0KDQo=" | base64 -d

echo -n "kernel version: "
uname -r

mount -t devtmpfs none /dev
mount -t proc proc /proc
mount -t sysfs sysfs /sys

modprobe virtio
modprobe virtio_ring
modprobe virtio_pci
modprobe virtio_net
modprobe 9pnet_virtio

chown root:0 /bin/busybox
chmod 4755 /bin/busybox
chown -R root:0 /bin
chown -R root:0 /etc
chown -R root:0 /lib
chown -R root:0 /root
chown -R root:0 /sbin
chown -R root:0 /usr
chown root:0 /
chown root:0 /init
chown root:0 /home

mkdir -p /share
mount -t 9p -o trans=virtio shared /share

# echo 1 > /proc/sys/kernel/kptr_restrict
# insmod /kmod.ko
# chmod a+rw /dev/vuln

setsid cttyhack setuidgid 1000 sh

umount /proc
umount /sys

poweroff -f
```

接下来安装modules到initramfs\_root中：

```
$ cd ../linux-4.13
$ make modules && make modules_install INSTALL_MOD_PATH=/home/vigi/CVE-2017-5123/initramfs_root/
```

此时，modules就会安装到initramfs\_root/lib文件夹中。

## 4. 准备好bzImage和initramfs.img使用Qemu启动内核

创建initramfs.img并准备好bzImage：

```
$ cd ../initramfs_root
$ find . |cpio -H newc -o | gzip > ../initramfs.img
$ cd ..
$ mv linux-4.13/arch/x86/boot/bzImage .
```

创建stratum.sh脚本并给予运行权限：

```
$ vim startvm.sh
$ chmod +x startvm.sh
$ cat startvm.sh
#!/bin/bash

if [ "$1" = "nokaslr" ]
then
    APPEND="console=ttyS0 loglevel=3 oops=panic panic=1 nokaslr"
else
    APPEND="console=ttyS0 loglevel=3 oops=panic panic=1"
fi

qemu-system-x86_64 \
    -s \
    -cpu kvm64,+smep,+smap \
    -nographic \
    -kernel bzImage \
    -initrd initramfs.img \
    -append "$APPEND" \
    -enable-kvm \
    -monitor /dev/null \
    -fsdev local,id=root,path=/tmp,security_model=none -device virtio-9p-pci,fsdev=root,mount_tag=shared
```

接下来就可以运行./startvm.sh启动kernel：

```
$ ./startvm.sh
 __                              .__                         
|  | __ ___________  ____   ____ |  |   ________  _  ______  
|  |/ // __ \_  __ \/    \_/ __ \|  |   \____ \ \/ \/ /    \ 
|    <\  ___/|  | \/   |  \  ___/|  |__ |  |_> >     /   |  \
|__|_ \\___  >__|  |___|  /\___  >____/ |   __/ \/\_/|___|  /
     \/    \/           \/     \/       |__|              \/ 

/ $
```

## 5. 使用gdb连接调试

启动好内核后就可以使用gdb连接调试了：

```
$ gdb vmlinux -q
Reading symbols from vmlinux...done.
(gdb) target remote :1234
Remote debugging using :1234
0xffffffffb93619b6 in ?? ()
(gdb)
```

带nokaslr参数就能在gdb中使用vmlinux得到更多调试信息。

```
$ ./startvm.sh nokaslr
```

```
$ gdb vmlinux -q
Reading symbols from vmlinux...done.
(gdb) target remote :1234
Remote debugging using :1234
default_idle () at arch/x86/kernel/process.c:342
342		trace_cpu_idle_rcuidle(PWR_EVENT_EXIT, smp_processor_id());
(gdb)
```

