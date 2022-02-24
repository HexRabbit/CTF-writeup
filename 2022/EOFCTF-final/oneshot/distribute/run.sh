#!/bin/bash

# /init will mount $SHARED_DIR to /mnt
# fill in some path you want to share with vm (e.g. /tmp)
SHARED_DIR=./shared

timeout 30 qemu-system-x86_64 \
  -kernel bzImage \
  -initrd rootfs.cpio.gz \
  -append "console=ttyS0 oops=panic panic=-1 kaslr kpti smep smap quiet" \
  -monitor /dev/null \
  -nographic \
  -cpu qemu64,+smep,+smap \
  -m 256M \
  -virtfs local,path=$SHARED_DIR,mount_tag=shared,security_model=passthrough,readonly
