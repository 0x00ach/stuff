echo "[-] local packages install"
# or manual install a debootstrap package (ubuntu .deb file, etc.)
apt-get install debootstrap
echo "[-] debootstrap `cat /etc/debian_version | sed -e "s/\/sid//"` i386 distrib"
mkdir chroot
# edit conf here (distrib and arch options)
debootstrap --arch=i386 `cat /etc/debian_version | sed -e "s/\/sid//"` chroot
cp /etc/hosts chroot/etc/hosts
cp /etc/resolv.conf chroot/etc/resolv.conf
cp chroot/sbin/initctl ./initctl.bak
# rename hostname here
echo "debian" > chroot/etc/hostname

echo "[-] custom install"
echo "mount none -t proc /proc && mount none -t sysfs /sys && mount none -t devpts /dev/pts && export HOME=/root && export LC_ALL=C" > chroot/root/build.sh
echo "apt-get update" >> chroot/root/build.sh
chmod +x chroot/root/build.sh
#change the kernel image if needed
image=`uname -r`
if [ `getconf LONG_BIT` == 64 ]
then
   image=`echo $image | sed s/amd64/486/`
fi
echo "apt-get install --no-install-recommends --yes linux-image-$image live-boot" >> chroot/root/build.sh
echo "apt-get install --no-install-recommends --yes vim wget nano" >> chroot/root/build.sh
#uncomment to install more packages
#echo "apt-get install network-manager net-tools wireless-tools wpagui tcpdump openssh-client xserver-xorg-core xserver-xorg xinit xterm pciutils usbutils gparted ntfsprogs hfsprogs rsync dosfstools syslinux partclone pv iceweasel xul-ext-adblock-plus xul-ext-https-everywhere chntpw" >> chroot/root/build.sh
echo "dbus-uuigen > chroot/var/lib/dbus/machine-id" >> chroot/root/build.sh
echo "rm /var/lib/dbus/machine-id" >> chroot/root/build.sh
echo "apt-get clean" >> chroot/root/build.sh
echo "rm -rf /tmp/*" >> chroot/root/build.sh
echo "rm -f chroot/etc/resolv.conf" >> chroot/root/build.sh
echo "apt-get clean && rm -rf /tmp/* && rm /etc/resolv.conf && umount -lf /proc && umount -lf /sys && umount -lf /dev/pts && exit" >> chroot/root/build.sh
chroot chroot /root/build.sh
rm chroot/root/build.sh

echo "OK, now just run \"chroot chroot\" and customize your system."
echo "If you plan doing lots of things, run (in chroot):"
echo "  \"mount none -t proc /proc && mount none -t sysfs /sys && mount none -t devpts /dev/pts && export HOME=/root && export LC_ALL=C\""
echo "Cleanup (in chroot too):"
echo "  \"apt-get clean && rm -rf /tmp/* && rm /etc/resolv.conf && umount -lf /proc && umount -lf /sys && umount -lf /dev/pts && exit\""
