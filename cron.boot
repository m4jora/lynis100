#!/bin/bash
#become su
if [ $EUID != 0 ]; then
  sudo "$0" "$@"
  exit $?
fi

#save shell entries, clear from usual location
cat /root/.bash_history >> /files/.root_bash_history
cat /home/${SUDO_USER}/.bash_history >> /files/.home_bash_history
echo "" | tee /root/.bash_history /home/${SUDO_USER}/.bash_history

#harden kernel parameters
kernel.modules_disabled=1
sysctl fs.suid_dumpable=0
sysctl kernel.sysrq=0
sysctl dev.tty.ldisc_autoload=0
sysctl fs.protected_fifos=2
sysctl kernel.core_uses_pid=1
sysctl kernel.kptr_restrict=2
sysctl kernel.modules_disabled=0
sysctl kernel.unprivileged_bpf_disabled=1
sysctl kernel.yama.ptrace_scope=1
sysctl net.core.bpf_jit_harden=2
sysctl net.ipv4.conf.all.accept_redirects=0
sysctl net.ipv4.conf.all.log_martians=1
sysctl net.ipv4.conf.all.rp_filter=1
sysctl net.ipv4.conf.all.send_redirects=0
sysctl net.ipv4.conf.default.accept_redirects=0
sysctl net.ipv4.conf.default.accept_source_route=0
sysctl net.ipv4.conf.default.log_martians=1
sysctl net.ipv6.conf.all.accept_redirects=0
sysctl net.ipv6.conf.default.accept_redirects=0

#remove common trashed files, old configs, and unnecessary packages
#upgrade outdated binaries
clear
rm /home/${SUDO_USER}/.local/share/gvfs-metadata/* /dev/shm/* /tmp/user/1000/* 2> /dev/null
aptitude purge
clear
apt-get purge $(apt list | grep 'residual-config' | sed 's/\/.*//' | tr -s '\n' ' ') 2> /dev/null
clear
apt-get autoremove
clear
apt-get update && apt-get upgrade -y && apt-get upgrade$(apt-get upgrade | grep -A 1 'kept back' | grep -v 'kept back') -y
clear

#establish iptable rules
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

#start daemons
systemctl start acct
systemctl start arpon
systemctl start arpwatch
arpwatch -i eno1
systemctl start arpalert
systemctl start auditd
systemctl start chkboot
systemctl start clamav-daemon
systemctl start clamav-freshclam
systemctl start netfilter-persistent
systemctl start nvidia-persistenced
systemctl start puppet
systemctl start sysstat
systemctl start usbguard-dbus
