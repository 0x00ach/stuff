echo "[-] start (needs ../debian.iso file)"
mkdir liveusb
cd liveusb
mkdir mnt

echo "[-] create F32 partition"
touch loop
dd if=/dev/zero of=loop bs=1 count=1 seek=300M
mkdosfs -F 32 -n rescue loop
mkdir tmp
mount -o loop ../debian.iso tmp
mount -o loop loop mnt

echo "[-] copy files"
cp -a tmp/* mnt/
cd mnt
mv isolinux/* .
rmdir isolinux
mv isolinux.bin syslinux.bin
mv isolinux.cfg syslinux.cfg
cd ..
umount mnt
umount tmp

echo "[-] syslinux"
syslinux loop
rmdir mnt
rmdir tmp

echo "[-] gzipping"
gzip -c loop > ../debian_live_usb.gz
rm loop
echo "run \"zcat debian_live_usb.gz | tee /dev/sdb1 > /dev/null\" to install into USB disk"
cd ..
rmdir liveusb
