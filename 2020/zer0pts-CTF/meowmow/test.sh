gcc exploit.c -static -o exp
cp exp rootfs
cd rootfs
find . | cpio -o --format=newc > ../modified.cpio
cd ..
./start.sh
