---
layout: article
title:  "Arm Linux Kernel调试环境搭建"
tags: pwn, exploit
---

_version_: 1.0

Linux Kernel + Busybox + Qemu

<!--more-->

## 1. 新建工作目录，如CVE-2013-6282

```
$ mkdir CVE-2013-6282
$ cd CVE-2013-6282
```

## 2. 下载Linaro

gcc-linaro-4.9.4-2017.01-x86_64_arm-linux-gnueabi.tar.xz
设置PATH：
```shell
$ export PATH=~/linaro-4.9-arm-linux-gnueabi/bin:$PATH
```

## 3. 编译kernel

```shell
$ wget https://cdn.kernel.org/pub/linux/kernel/v3.x/linux-3.5.tar.xz
$ tar xf linux-3.5.tar.xz
$ cd linux-3.5
$ ARCH=arm CROSS_COMPILE=arm-linux-gnueabi- make vexpress_defconfig
$ ARCH=arm CROSS_COMPILE=arm-linux-gnueabi- make menuconfig
$ vim .config
```

需要注意的有:
```
General setup -> [*] open by fhandle syscalls
Kernel Features -> [*] Use the ARM EABI to compile the kernel
                   [*] Allow old ABI binaries to run with this kernel
Device Drivers -> Generic Driver Options -> [*] Maintain a devtmpfs filesystem to mount at /dev
                                            [*] Automount devtmpfs at /dev, after the kernel mounted the rootfs
Kernel hacking -> [*] Kernel debugging
                  [*] Compile the kernel with debug info
```

```shell
$ ARCH=arm CROSS_COMPILE=arm-linux-gnueabi- make -j4
$ cd ..
```

## 4. 使用busybox创建initramfs

```shell
$ wget https://busybox.net/downloads/busybox-1.28.1.tar.bz2
$ tar xf busybox-1.28.1.tar.bz2
$ cd busybox-1.28.1
$ ARCH=arm CROSS_COMPILE=arm-linux-gnueabi- make defconfig
$ ARCH=arm CROSS_COMPILE=arm-linux-gnueabi- make -j4 CFLAGS=-static install
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

chown root:0 /bin/busybox
chmod 4755 /bin/busybox

setsid cttyhack setuidgid 1000 sh

umount /proc
umount /sys

poweroff -f
```

接下来安装modules到rootfs中：
```shell
$ cd ../linux-3.5
$ sudo cp -P ~/arm-linux-gnueabi/lib/* /home/vigi/CVE-2013-6282/rootfs/lib/
$ ARCH=arm CROSS_COMPILE=arm-linux-gnueabi- make modules && make modules_install INSTALL_MOD_PATH=/home/vigi/CVE-2013-6282/rootfs/
```

## 5. 准备好zImage和rootfs.img使用Qemu启动内核

创建rootfs.img并准备好zImage：
```shell
$ cd ../rootfs
$ find . |cpio -H newc -o | gzip > ../rootfs.img
$ cd ..
$ mv linux-3.5/arch/arm/boot/zImage .
```

创建stratum.sh脚本并给予运行权限：

```
$ vim startvm.sh
$ chmod +x startvm.sh
$ cat startvm.sh
#!/bin/bash

if [ "$1" = "nokaslr" ]
then
    APPEND="root=/dev/ram console=ttyAMA0 loglevel=3 oops=panic panic=1 nokaslr"
else
    APPEND="root=/dev/ram console=ttyAMA0 loglevel=3 oops=panic panic=1"
fi

qemu-system-arm \
    -s \
    -M vexpress-a9 \
    -m 512M \
    -nographic \
    -kernel zImage \
    -initrd rootfs.img \
    -append "$APPEND"
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

kernel version: 3.5.0
/ $
```

## 6. 使用gdb连接调试

启动好内核后就可以使用gdb连接调试了：

```
$ arm-linux-gnueabi-gdb vmlinux -q
Reading symbols from vmlinux...done.
(gdb) target remote :1234
Remote debugging using :1234
cpu_v7_do_idle () at arch/arm/mm/proc-v7.S:74
74      mov pc, lr
(gdb)
```
