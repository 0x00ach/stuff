rm -rf image
echo "[-] Cleaning"
chroot chroot apt-get clean
find chroot/ -type f -name .bash_history -exec rm {} \;

echo "[-] Install packages"
apt-get install syslinux squashfs-tools genisoimage

echo "[-] Custom image"
mkdir -p image/{live,isolinux,install}

for file in chroot/boot/vmlinuz-**; do cp $file image/live/vmlinuz; done
for file in chroot/boot/initrd.img-**; do cp $file image/live/initrd.lz; done
if [ -f /usr/lib/syslinux/isolinux.bin ]
then
  cp /usr/lib/syslinux/isolinux.bin image/isolinux/
else
  if [ -f /usr/lib/vmware/resources/isolinux.bin ]
  then
     cp /usr/lib/vmware/resources/isolinux.bin image/isolinux/
  else
     echo "[!] isolinux.bin not found"
     rm -rf image
     exit 1
  fi
fi

cp /boot/memtest86+.bin image/install/memtest

echo "Press ENTER to boot" > image/isolinux/isolinux.txt
echo "DEFAULT live" >> image/isolinux/isolinux.cfg
echo "LABEL live" >> image/isolinux/isolinux.cfg
echo "  menu label ^Start or install Ubuntu Remix" >> image/isolinux/isolinux.cfg
echo "  kernel /live/vmlinuz" >> image/isolinux/isolinux.cfg
echo "  append  boot=live initrd=/live/initrd.lz" >> image/isolinux/isolinux.cfg
echo "DISPLAY isolinux.txt" >> image/isolinux/isolinux.cfg
echo "TIMEOUT 300" >> image/isolinux/isolinux.cfg
echo "PROMPT 1" >> image/isolinux/isolinux.cfg

echo "[-] Manifests"
chroot chroot dpkg-query -W --showformat='${Package} ${Version}\n' | tee image/live/filesystem.manifest
cp -v image/live/filesystem.manifest image/live/filesystem.manifest-desktop

echo "[-] SquashFS making"
mksquashfs chroot image/live/filesystem.squashfs -e boot
printf $(du -sx --block-size=1 chroot | cut -f1) > image/live/filesystem.size
(cd image && find . -type f -print0 | xargs -0 md5sum | grep -v "\./md5sum.txt" > md5sum.txt)

echo "[-] ISO making"
cd image
genisoimage -r -V "$IMAGE_NAME" -cache-inodes -J -l -b isolinux/isolinux.bin -c isolinux/boot.cat -no-emul-boot -boot-load-size 4 -boot-info-table -o ../debian.iso .
cd ..
rm -rf image

