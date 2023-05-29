#!/usr/bin/env bash

##########################################################################################
### USE AT YOUR OWN RISK!                                                              ###
### This script is intended to increase security on a fresh install of Debian Bookworm,###
### but it may cause unintended consequences, including decreased functionality,       ###    
### volatile runtimes and crashing. You may want to test this in a virtual machine!    ###
##########################################################################################

#switch to su
if [ $EUID != 0 ]; then
    sudo "$0" "$@"
    exit $?
fi

#upgrade packages
apt-get update && apt-get upgrade -y && apt-get upgrade$(apt-get upgrade | grep -A 1 'kept back' | grep -v 'kept back') -y
clear
#get sec utils
apt-get install -y acct aptitude apt-listbugs apt-listchanges apt-show-versions apt-transport-https arpon arpwatch auditd autolog bleachbit build-essential chkrootkit chkboot clamav clamtk clamav-daemon debsums fail2ban git gzip iptables iptables-persistent john john-data libapache2-mod-evasive libapache2-mod-security2 libpam-tmpdir libpam-passwdqc lynis menu needrestart net-tools nmap puppet resolvconf rng-tools rsync ssh-audit sysstat tar tiger trash-cli tripwire usbguard
clear

#acct
mkdir /var/log/account
chmod -R 755 /var/log/account
touch /var/log/account/pacct
systemctl enable acct
clear

#aide
apt-get install aide aide-common -y
sed -i '/Checksums/s/H/sha512/;/report_ignore_e2fsattrs/s/^/#/' /etc/aide/aide.conf
cp -f /etc/aide/aide.conf /usr/local/etc/aide.conf
cp -f /etc/aide/aide.conf /usr/share/aide/config/aide/aide.conf
echo ""
declare y="null";
echo "Aide Initialization may take a long time!"
aide -i
clear

#arp monitoring
chmod 750 -R /var/lib/arpalert
chown arpalert /var/lib/arpalert
systemctl enable arpalert
systemctl enable arpon
systemctl enable arpwatch
arpwatch -i eno1
clear

#auditd update rules
mkdir /var/log/audit
touch /var/log/audit/audit.log
chmod -R 775 /var/log/audit
systemctl enable auditd
systemctl start auditd
cp -f audit.rules /etc/audit/rules.d/audit.rules
systemctl restart auditd
systemctl stop auditd
clear

#chkboot
systemctl enable chkboot
clear

#clamav daemons
systemctl enable clamav-daemon
systemctl enable clamav-freshclam
clear

#compiler permissions
chmod 700 /usr/bin/x86_64-linux-gnu-as
chmod 700 /usr/bin/x86_64-linux-gnu-gc*

#coredump
sed -i '/soft    core/s/#//' /etc/security/limits.conf
echo "* hard core 0" >> /etc/security/limits.conf
printf "%s\nProcessSizeMax=0\nStorage=none" >> /etc/systemd/coredump.conf

#cups
sed -i '/run/s/^/#/' /etc/cups/cupsd.conf
chmod 400 /etc/cups/cupsd.conf

#/etc/fstab harden partitions
declare fstype="FILESYSTEMTYPE";
fstype=$(grep 'var' /etc/fstab | sed 's/.*var //;s/ .*//');
sed -i "/var/s/var.*/var ${fstype} nodev,nosuid 0 2/" /etc/fstab
fstype=$(grep 'home' /etc/fstab | sed 's/.*home //;s/ .*//');
sed -i "/home/s/home.*/home ${fstype} nodev,noexec,nosuid 0 2/" /etc/fstab
fstype=$(grep 'usr' /etc/fstab | sed 's/.*usr //;s/ .*//');
sed -i "/usr/s/usr.*/usr ${fstype} nodev 0 2/" /etc/fstab
fstype=$(grep '\/ ' /etc/fstab | sed 's/.*\/ //;s/ .*//');
sed -i "/\/ /s/\/.*/\/ ${fstype} defaults 0 1" /etc/fstab
fstype=$(grep 'opt' /etc/fstab | sed 's/.*opt //;s/ .*//');
sed -i "/opt/s/opt.*/opt ${fstype} nodev,nosuid 0 2" /etc/fstab
#corresponding filesystems
echo "tmpfs /tmp tmpfs rw,mode=1777,size=4g 0 0" >> /etc/fstab
echo "proc /proc proc hidepid=2 0 0" >> /etc/fstab
#encrypted swap
sed -i '/swap/s/^.*//' /etc/fstab
echo "/dev/mapper/sw none swap defaults 0 0" >> /etc/fstab
declare swapuuid=$(blkid | grep swap | sed 's/ TYPE.*//;s/\"//g;s/.*U/UU/');
dd if=/dev/random of=/root/.ssh/thepasswd bs=1K count=4
echo "sw $swapuuid /root/.ssh/thepasswd swap" >> /etc/crypttab
update-grub
mount -a
systemctl daemon-reload
clear

#/etc/login.defs
sed -i 's/022/027/;s/99999/180/;s/MIN_DAYS	0/MIN_DAYS	7/;/LOGIN_RETRIES/s/5/3/;/CRYPT_MIN/s/#//;/CRYPT_MIN/s/5/25/;/CRYPT_MAX/s/#//;/CRYPT_MAX/s/000/0000/;s/ SHA/SHA/' /etc/login.defs
passwd -n 15 -x 90 ${SUDO_USER}
clear

#/etc/ssh/sshd_config
sed -i '/AllowTcpForwarding/s/#//;/AllowTcpForwarding/s/yes/no/;/ClientAliveCountMax/s/#//;/ClientAliveCountMax/s/3/2/;/Compression/s/#//;/Compression/s/delayed/no/;/LogLevel/s/#//;/LogLevel/s/INFO/VERBOSE/;/MaxAuthTries/s/#//;/MaxAuthTries/s/6/3/;/MaxSessions/s/#//;/MaxSessions/s/10/2/;/Port/s/#//;/Port/s/22/1001/;/TCPKeepAlive/s/#//;/TCPKeepAlive/s/yes/no/;/X11Forwarding/s/#//;/X11Forwarding/s/yes/no/;/AllowAgentForwarding/s/#//;/AllowAgentForwarding/s/yes/no/;s/	/#/;s/##/#/;/Subsystem/s/#//' /etc/ssh/sshd_config

#fail2ban backup config
cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local

#file/dir permissions
chmod 700 -R $(ls -l /etc | grep cron | grep -v '^-' | sed 's/.* //;s/^/\/etc\//' | tr -s '\n' ' ')
chmod 600 /etc/crontab
chmod 600 /etc/ssh/sshd_config
chmod 600 /boot/grub/grub.cfg
chmod 700 /etc/sudoers.d

#grub pbkdf2 password
clear
echo "Ok. Here comes the tricky part..."
echo ""
echo "After pressing [Return] to continue, you'll be establishing a GRUB username and password to be entered at boot, before your operating system is mounted."
echo "Your username will be visible as you type it, but your password will not be."
echo "Be sure to enter the password correctly, as not doing so will lock you out of your system."
echo ""
declare q="n";
read -p "Continue? [y/n]: " q
if [ $q == 'n' ]||[ $q == 'N' ]; then
exit
fi
clear
declare loggin="";
read -p "Username?: " loggin
echo "cat <<EOF" >> /etc/grub.d/00_header
printf "%sset superusers=\"${loggin}\"\npassword_pbkdf2 ${loggin} " >> /etc/grub.d/00_header
echo "Enter password twice and press [Return] after each entry: "
printf $(grub-mkpasswd-pbkdf2 | sed -n '3p' | cut -c 33-) >> /etc/grub.d/00_header
echo "" >> /etc/grub.d/00_header
echo "EOF" >> /etc/grub.d/00_header
update-grub
clear

#iptables DoS prevention, drop invalid traffic, block common vulnerable ports
iptables -A INPUT -p tcp --dport 80 -m limit --limit 25/minute --limit-burst 100 -j ACCEPT
iptables -A INPUT -m conntrack --ctstate INVALID -j DROP
iptables -A OUTPUT -p tcp --dport 135 -j DROP
iptables -A OUTPUT -p udp --dport 135 -j DROP
iptables -A OUTPUT -p tcp --dport 137 -j DROP
iptables -A OUTPUT -p udp --dport 137 -j DROP
iptables -A OUTPUT -p tcp --dport 138 -j DROP
iptables -A OUTPUT -p udp --dport 138 -j DROP
iptables -A OUTPUT -p tcp --dport 139 -j DROP
iptables -A OUTPUT -p udp --dport 139 -j DROP
iptables -A OUTPUT -p tcp --dport 445 -j DROP
iptables -A OUTPUT -p udp --dport 69 -j DROP
iptables -A OUTPUT -p udp --dport 514 -j DROP
iptables -A OUTPUT -p udp --dport 161 -j DROP
iptables -A OUTPUT -p udp --dport 163 -j DROP
iptables -A OUTPUT -p tcp --dport 6660 -j DROP
iptables -A OUTPUT -p tcp --dport 6661 -j DROP
iptables -A OUTPUT -p tcp --dport 6662 -j DROP
iptables -A OUTPUT -p tcp --dport 6663 -j DROP
iptables -A OUTPUT -p tcp --dport 6664 -j DROP
iptables -A OUTPUT -p tcp --dport 6665 -j DROP
iptables -A OUTPUT -p tcp --dport 6666 -j DROP
iptables -A OUTPUT -p tcp --dport 6667 -j DROP
iptables -A OUTPUT -p tcp --dport 6668 -j DROP
iptables -A OUTPUT -p tcp --dport 6669 -j DROP
iptables-save
clear

#iptables netfilter
systemctl enable netfilter-persistent
clear

#nvidia (if you have it)
systemctl enable nvidia-persistenced
clear

#modprobe to disable rare protocols
for i in {dccp,sctp,rds,tipc,freevxfs,hfs,hfsplus,jffs2,udf}
do
echo "install $i /bin/true" > /etc/modprobe.d/${i}.conf
done
printf "%sblacklist dccp\nblacklist sctp\nblacklist tipc\nblacklist rds" > /etc/modprobe.d/blacklist-rare.conf
echo "blacklist firewire-core" > /etc/modprobe.d/firewire.conf
printf "%sblacklist freevxfs\nblacklist hfs\nblacklist hfsplus\nblacklist jffs2\nblacklist udf" > /etc/modprobe.d/blacklist-fs.conf
modprobe -rb freevxfs hfs hfsplus jffs2 udf dccp sctp rds tipc firewire-core
clear

#non-native binaries
apt-get remove llvm-14-runtime llvm-15-runtime -y
clear

#puppet
systemctl enable puppet
clear

#ssh banner
echo "Attention, by continuing to connect to this system, you consent to the owner storing a log of all activity. Unauthorized access is prohibited." | tee /etc/issue{,.net}

#sysstat
sed -i 's/false/true/' /etc/default/sysstat
systemctl enable sysstat
clear

#trash
trash-empty
rm /home/${SUDO_USER}/.local/share/Trash/expunged/* /home/${SUDO_USER}/.local/share/Trash/files/* /home/${SUDO_USER}/.local/share/Trash/info/* 2> /dev/null
rm -rf /home/${SUDO_USER}/.local/share/Trash/expunged/* /home/${SUDO_USER}/.local/share/Trash/files/* /home/${SUDO_USER}/.local/share/Trash/info/* 2> /dev/null
clear

#ulimit and umask
umask 027
printf '%sulimit -c 0\numask 027' >> /etc/profile
sed -i '1s/^/umask 027\n/' /etc/bash.bashrc

#usbguard
usbguard generate-policy -p
sed -i 's/Inserted.*/InsertedDevicePolicy=block/' /etc/usbguard/usbguard-daemon.conf
sed -i 's/PresentControllerPolicy=.*/PresentControllerPolicy=apply-policy/' /etc/usbguard/usbguard-daemon.conf
systemctl enable usbguard-dbus
clear

#WRAP. IT. UP!
echo "It is HIGHLY reccomended that you reboot!"
echo ""
declare x="null";
read -p "Press Ctrl+C to Abort Reboot or [Return] to complete installation..." x
reboot
