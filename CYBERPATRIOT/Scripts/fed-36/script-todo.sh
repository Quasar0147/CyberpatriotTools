##TODO:
# 1.  Fix Ctrl alt del
# 2.  Fix systemd
# 3.  Recalculate sysctl
# remove gpasswds
authselect opt-out
dnf install -y audit
dnf install dnf-automatic -y
dnf install gedit -y
dnf install firewalld -y
dnf install rsyslog -y
for x in $(cat /etc/group | cut -d: -f1)
do
gpasswd -r $x
done

# open up group passwd and fstab via gedit
gedit /etc/group &
gedit /etc/passwd &
gedit /etc/fstab &

# remove cups, bluetooth, and apport
dnf remove -y cups
dnf remove -y bluetooth
dnf remove -y apport
#chown and chmod utils
chmod 644 utils/*
chown root:root utils/*

# clear crontabs and atq
for u in $(cat /etc/passwd | grep -E "/bin/.*sh" | cut -d":" -f1)
do
crontab -u $u -r
done
for i in `atq | awk '{print $1}'`;do atrm $i;done
rm -f /etc/cron.deny /etc/at.deny
echo root >/etc/cron.allow
echo root >/etc/at.allow
chown root:root /etc/cron.allow /etc/at.allow
chmod 644 /etc/cron.allow /etc/at.allow
chown -R root:root /var/spool/cron
chmod -R 644 /var/spool/cron
chown -R root:root /etc/*cron*
chmod -R 644 /etc/*cron*

# copy systemd configs in
#cp `pwd`/utils/systemd/* /etc/systemd/
cp `pwd`/utils/systemd/coredump.conf /etc/systemd/
cp `pwd`/utils/systemd/journald.conf /etc/systemd/
cp `pwd`/utils/systemd/logind.conf /etc/systemd/
cp `pwd`/utils/systemd/pstore.conf /etc/systemd/
cp `pwd`/utils/systemd/oomd.conf /etc/systemd/

# set umask
umask 0077

# remove alternatives to /etc/profile
rm -r /etc/profile.d/*

#reset rsyslog config
# rm /etc/rsyslog.conf
#sdnf reinstall rsyslog -y
systemctl start rsyslog
systemctl enable rsyslog

# set passwords
password="Baher13@c0stc0"
for u in $(cat /etc/passwd | grep -E "/bin/.*sh" | cut -d":" -f1); do echo "$u:$password" | chpasswd; echo "$u:$password"; done


# configure firewalld
#rm -r /etc/firewalld/*
#rm -r /usr/lib/firewalld/*
#dnf reinstall firewalld -y
systemctl start firewalld
systemctl enable firewalld
firewall-cmd --set-log-denied=all
firewall-cmd --set-default-zone=drop
# Deny outbound traffic
#firewall-cmd --permanent --zone=drop --add-rich-rule='rule family="ipv4" source address="0.0.0.0/0" reject'
#firewall-cmd --zone=drop --add-rich-rule='rule family="ipv4" source address="0.0.0.0/0" reject'
#firewall-cmd --permanent --direct --add-rule ipv4 filter OUTPUT 0 -j REJECT
#firewall-cmd --direct --add-rule ipv4 filter OUTPUT 0 -j REJECT
#firewall-cmd --permanent --direct --add-rule ipv6 filter OUTPUT 0 -j REJECT
#firewall-cmd --direct --add-rule ipv6 filter OUTPUT 0 -j REJECT
#firewall-cmd --permanent --zone=drop --add-rich-rule='rule family="ipv6" source address="::1" reject'
#firewall-cmd --zone=drop --add-rich-rule='rule family="ipv6" source address="::1" reject'
#Deny Routed Traffic via direct
firewall-cmd --permanent --direct --add-rule ipv4 filter FORWARD 0 -j REJECT
firewall-cmd --direct --add-rule ipv4 filter FORWARD 0 -j REJECT
firewall-cmd --permanent --direct --add-rule ipv6 filter FORWARD 0 -j REJECT
firewall-cmd --direct --add-rule ipv6 filter FORWARD 0 -j REJECT

cp `pwd`/utils/firewalld.conf /etc/firewalld/firewalld.conf
cp `pwd`/utils/firewalld.conf /etc/firewalld/firewalld-workstation.conf
cp `pwd`/utils/firewalld.conf /etc/firewalld/firewalld-server.conf

# copy pam from utils
cp `pwd`/utils/system-auth /etc/pam.d/
cp /etc/pam.d/system-auth /etc/pam.d/password-auth

# set dates for users
#--inactive 31  --expiredate 0 
for x in $(awk -F: '($3>=1000)&&($1!="nobody"){print $1}' /etc/passwd); do chage --mindays 7 --maxdays 30 --warndays 15 --lastday 0 $x; done

# copy lightdm config from utils
cp `pwd`/utils/lightdm/* /etc/lightdm/

# copy gdm3 config from utils
cp `pwd`/utils/gdm3.conf /etc/gdm3/custom.conf
echo "user-db:user
system-db:gdm
file-db:/usr/share/gdm/greeter-dconf-defaults
" >> /etc/dconf/profile/user
chmod 644 /etc/dconf/profile/user
chown root:root /etc/dconf/profile/user
rm /etc/dconf/db/gdm.d/* 2>/dev/null
rm /home/*/.config/dconf/user 2>/dev/null
mkdir /etc/dconf/db/gdm.d/ 2>/dev/null
cp `pwd`/utils/greeter.dconf-defaults /etc/gdm3/greeter.dconf-defaults
cp `pwd`/utils/greeter.dconf-defaults /usr/share/gdm/greeter.dconf-defaults
cp /etc/gdm3/greeter.dconf-defaults /usr/share/gdm/greeter.dconf-defaults
cp `pwd`/utils/greeter.dconf-defaults /etc/dconf/db/gdm.d/*
chmod 644 /etc/dconf/db/gdm.d/*
mkdir /etc/dconf/db/gdm.d/locks/ 2>/dev/null
cp `pwd`/utils/gdm-lockfile /etc/dconf/db/gdm.d/locks/00-security-settings-lock
chmod 644 /etc/dconf/db/gdm.d/00-login-screen
chown root:root /etc/dconf/db/gdm.d/00-login-screen
dconf update

# copy in pwquality
cp `pwd`/utils/pwquality.conf /etc/security/pwquality.conf

# copy in login.defs
cp `pwd`/utils/login.defs /etc/login.defs

# copy in selinux configs
cp `pwd`/utils/selinux/* /etc/selinux

# copy in grub
cp ./utils/grub /etc/default/grub
chmod 644 /etc/default/grub
chown root:root /etc/default/grub
data="grub.pbkdf2.sha512.10000.397910689ECC4DA5196D28748B37DA4E88C4A0C57E8E741ED6C8DE9CC93A082DC4C7A70EC70DD3637BC4A2AA251A973881C67ED2643AB7B2AC293771683FF963.E8463183C35EB90E0C9E3FACE89B4AA2F1E139DAE0D4B8F847CE2A0BF83705041956123D4E9A3419F1EB31DCB8A5F57FF85DBD00F1FA85659D74AF33779894BE"
echo "cat <<EOF
set superusers='root'
password pbkdf2 root '"$data"'
EOF" >> /etc/grub.d/00_header
sed -i "s/set superusers=.*/set superusers='root'/g" /etc/grub.d/*
chmod 744 /etc/grub.d/00_header
# copy in sysctl
cp `pwd`/utils/sysctl.conf /etc/sysctl.conf
cp /etc/sysctl.conf /etc/sysctl.d/* 2> /dev/null

# config ipv6
read -p "IPV6? (y/n): " ipv6
if [ "$ipv6"="y" ]; then
echo "
net.ipv6.conf.all.accept_ra=0
net.ipv6.conf.all.accept_redirects=0
net.ipv6.conf.all.accept_source_route=0
net.ipv6.conf.all.forwarding=0
net.ipv6.conf.all.use_tempaddr=2
net.ipv6.conf.default.accept_ra=0
net.ipv6.conf.default.accept_ra_defrtr=0
net.ipv6.conf.default.accept_ra_pinfo=0
net.ipv6.conf.default.accept_ra_rtr_pref=0
net.ipv6.conf.default.accept_redirects=0
net.ipv6.conf.default.accept_source_route=0
net.ipv6.conf.default.autoconf=0
net.ipv6.conf.default.dad_transmits=0
net.ipv6.conf.default.max_addresses=1
net.ipv6.conf.default.router_solicitations=0
net.ipv6.conf.default.use_tempaddr=2
net.ipv6.conf.all.accept_ra_rtr_pref=0
net.ipv6.conf.all.accept_ra_pinfo=0
net.ipv6.conf.all.accept_ra_defrtr=0
net.ipv6.conf.all.use_tempaddr=2
net.ipv6.conf.default.use_tempaddr=2
" >> /etc/sysctl.conf
#echo "ipv6.disable=0" >> /etc/default/grub
else 
echo "net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1" >> /etc/sysctl.conf
sed -i "s/GRUB_CMDLINE_LINUX_DEFAULT=.*/GRUB_CMDLINE_LINUX_DEFAULT=\"ipv6.disable=1\"/g" /etc/default/grub
fi
#grub2-mkconfig -o "$(readlink -e /etc/grub2.cfg)"
sysctl -p /etc/sysctl.conf 0>1 1>/dev/null
sysctl --system >/dev/null
# Misc Permissions
chmod 744 /etc/default/grub
chown root:root /boot/grub/grub.cfg 2>/dev/null
chmod 744 /boot/grub/grub.cfg 2>/dev/null
chown root:root /etc/crontab 2>/dev/null
chmod og-rwx /etc/crontab 2>/dev/null
chown root:root /etc/cron.hourly 2>/dev/null
chmod og-rwx /etc/cron.hourly 2>/dev/null
chown root:root /etc/cron.daily 2>/dev/null 
chmod og-rwx /etc/cron.daily 2>/dev/null
chown root:root /etc/cron.weekly 2>/dev/null
chmod og-rwx /etc/cron.weekly 2>/dev/null
chown root:root /etc/cron.monthly 2>/dev/null
chmod og-rwx /etc/cron.monthly 2>/dev/null
chown root:root /etc/cron.d 2>/dev/null
chmod og-rwx /etc/cron.d 2>/dev/null
rm /etc/cron.deny 2>/dev/null
rm /etc/at.deny 2>/dev/null
chown -R root:root /etc/*cron*
chmod -R 600 /etc/*cron*
chown -R root:root /var/spool/cron
chmod -R 600 /var/spool/cron
touch /etc/cron.allow 2>/dev/null
touch /etc/at.allow 2>/dev/null
chmod og-rwx /etc/cron.allow 2>/dev/null
chmod og-rwx /etc/at.allow 2>/dev/null
chown root:root /etc/cron.allow 2>/dev/null
chown root:root /etc/at.allow 2>/dev/null
chown root:root /etc/passwd 2>/dev/null
chmod 0744 /etc/passwd 2>/dev/null
chown root:shadow /etc/shadow 2>/dev/null
chmod o-rwx,g-wx /etc/shadow 2>/dev/null
chown root:root /etc/group 2>/dev/null
chmod 0700 /etc/group 2>/dev/null
chmod 0644 /etc/group 2>/dev/null
chown root:root /etc/group- 2>/dev/null
chmod u-x,go-wx /etc/group- 2>/dev/null
chown root:shadow /etc/gshadow 2>/dev/null
chmod o-rwx,g-rw /etc/gshadow 2>/dev/null
chown root:root /etc/passwd- 2>/dev/null
chmod u-x,go-wx /etc/passwd- 2>/dev/null
chown root:root /etc/shadow- 2>/dev/null
chown root:shadow /etc/shadow- 2>/dev/null
chmod o-rwx,g-rw /etc/shadow- 2>/dev/null
chown root:root /etc/gshadow- 2>/dev/null
chown root:shadow /etc/gshadow- 2>/dev/null
chmod o-rwx,g-rw /etc/gshadow- 2>/dev/null
chown root:root /etc/motd 2>/dev/null
chmod 0744 /etc/motd 2>/dev/null
chown root:root /etc/issue 2>/dev/null
chmod 0744 /etc/issue 2>/dev/null
chown root:root /etc/issue.net 2>/dev/null
chmod 0744 /etc/issue.net 2>/dev/null
chown root:root /etc/hosts.allow 2>/dev/null
chmod 0744 /etc/hosts.allow 2>/dev/null
chown root:root /etc/hosts.deny 2>/dev/null
chmod 0744 /etc/hosts.deny 2>/dev/null
chown root:root /etc/hosts 2>/dev/null
chmod 0744 /etc/hosts 2>/dev/null
chown root:root /etc/hostname 2>/dev/null
chmod 0744 /etc/hostname 2>/dev/null
chown root:root /etc/network/interfaces 2>/dev/null
chmod 0744 /etc/network/interfaces 2>/dev/null
chown root:root /etc/network/interfaces.d 2>/dev/null
chmod 0744 /etc/network/interfaces.d 2>/dev/null
chown root:root /etc/networks 2>/dev/null
chmod 0744 /etc/networks 2>/dev/null
chown root:root /etc/services 2>/dev/null
chmod 0744 /etc/services 2>/dev/null
chown root:root /etc/protocols 2>/dev/null
chmod 0744 /etc/protocols 2>/dev/null
chown root:root /etc/resolv.conf 2>/dev/null
chmod 0744 /etc/resolv.conf 2>/dev/null
chown root:root /etc/nsswitch.conf 2>/dev/null
chmod 0744 /etc/nsswitch.conf 2>/dev/null
chown root:root /etc/ssh/sshd_config 2>/dev/null
chmod 0744 /etc/ssh/sshd_config 2>/dev/null
chown root:root /etc/ssh/ssh_config 2>/dev/null
chmod 0744 /etc/ssh/ssh_config 2>/dev/null
chown root:root /etc/ssh/moduli 2>/dev/null
chmod 0744 /etc/ssh/moduli 2>/dev/null
chown root:root /etc/ssh/ssh_host_rsa_key 2>/dev/null
chmod 400 /etc/ssh/ssh_host_rsa_key 2>/dev/null
chown root:root /etc/ssh/ssh_host_dsa_key 2>/dev/null
chmod 400 /etc/ssh/ssh_host_dsa_key 2>/dev/null
chown root:root /etc/ssh/ssh_host_ecdsa_key 2>/dev/null
chmod 400 /etc/ssh/ssh_host_ecdsa_key 2>/dev/null
chown root:root /etc/ssh/ssh_host_ed25519_key 2>/dev/null
chmod 400 /etc/ssh/ssh_host_ed25519_key 2>/dev/null
chown root:root /etc/ssh/ssh_host_rsa_key.pub 2>/dev/null
chmod 744 /etc/ssh/ssh_host_rsa_key.pub 2>/dev/null
chown root:root /etc/ssh/ssh_host_dsa_key.pub 2>/dev/null
chmod 744 /etc/ssh/ssh_host_dsa_key.pub 2>/dev/null
chown root:root /etc/ssh/ssh_host_ecdsa_key.pub 2>/dev/null
chmod 744 /etc/ssh/ssh_host_ecdsa_key.pub 2>/dev/null
chown root:root /etc/ssh/ssh_host_ed25519_key.pub 2>/dev/null
chmod 744 /etc/ssh/ssh_host_ed25519_key.pub 2>/dev/null
chown root:root /lib 
chown root:root /usr/lib 
chown root:root /lib64
chown root:root /etc/pam.d/* /etc/pam.conf /etc/login.defs /etc/security/*
chmod 0644 /etc/pam.d/* /etc/pam.conf /etc/login.defs /etc/security/*
chgrp adm /var/log/syslog
chmod 0750 /var/log
chown root:root /etc/securetty
chmod 0600 /etc/securetty
chmod 0644 /etc/hosts.allow
chmod 0440 /etc/sudoers
find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin ! -user root -type d -exec chown root:root '{}' +;
find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -perm /022 -type d -exec chmod -R 755 '{}' +;
find /lib /lib64 /usr/lib -perm /022 -type f -exec chmod 755 '{}' +;
find /lib /lib64 /usr/lib -perm /022 -type d -exec chmod 755 '{}' +;
find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -perm /022 -type f -exec chmod 755 '{}' +;
chown root:root /var/log
find /var/log -perm /137 -type f -exec chmod 640 '{}' \;
find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin ! -user root -type f -exec  -c chown root:root '{}' +;
find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -name "*.sh" -type f -delete
chmod 700 /boot /usr/src /lib/modules /usr/lib/modules
chmod 744 /etc/security/limits.conf
chmod 600 /etc/ssh/*key 2>/dev/null
chmod 640 /etc/ssh/*key.pub 2>/dev/null
chmod 640 /etc/ssh/*key-cert.pub 2>/dev/null
chmod 0640 /var/log/syslog
chown root:root /var/log/syslog
# copy auditd configs
systemctl enable auditd
systemctl start auditd
cp `pwd`/utils/auditd.conf /etc/audit/auditd.conf
auditctl -e 1
#rm /etc/audit/rules.d/*
sed -i "s/active=.*/active=no/gI" /etc/audit/plugins.d/*
cp `pwd`/utils/audit.rules /etc/audit/rules.d/audit.rules
augenrules --load
chmod -R  g-w,o-rwx /var/log/audit
chmod -R 0640 /etc/audit/audit*.{rules,conf} /etc/audit/rules.d/*
chown root:root /etc/audit/audit*.{rules,conf} /etc/audit/rules.d/*
chmod 744 /etc/audit/auditd.conf
systemctl kill auditd -s SIGHUP
systemctl restart auditd
chown root:root /var/log/audit/audit.log
# lock all user accs
#for u in $(cat /etc/passwd | grep -E "/bin/.*sh" | cut -d":" -f1); do passwd -l $u; done

#limits.conf
echo "* hard core
* hard maxlogins 10
* hard maxsyslogins 20
* hard fsize 10000000
* hard nofile 1024
* hard nproc 1024
" > /etc/security/limits.conf
chmod 744 /etc/security/limits.conf

# Disabling some modules
for x in "sctp tipc rds"; do modprobe -n -v $x; echo "install $x /bin/true" >> /etc/modprobe.d/modules.conf; done
chmod 744 /etc/modprobe.d/modules.conf 2>/dev/null

# Clear rc.local
echo > /etc/rc.local

#Config other rcs
cp `pwd`/utils/bashrc /etc/bashrc
cp `pwd`/utils/profile /etc/profile
chmod 644 /etc/profile
cp /etc/profile /home/*/.profile
cp /etc/profile /root/.profile
chmod 644 /home/*/.profile
chmod 644 /root/.profile
chmod 644 /etc/bashrc
cp /etc/bashrc /home/*/.bashrc
cp /etc/bashrc /root/.bashrc
chmod 644 /home/*/.bashrc
chmod 644 /root/.bashrc

# Purge Games
#dnf remove aisleriot gnome-sudoku mahjongg ace-of-penguins gnomine gbrainy gnome-sushi gnome-taquin gnome-tetravex gnome-robots gnome-chess lightsoff swell-foop quadrapassel telnet telnetd >> /dev/null


# Clear securetty
echo "" > /etc/securetty

# Configure faillock
echo "
audit
silent
fail_interval=900
unlock_time=600
even_deny_root
deny = 3
" > /etc/security/faillock.conf
#disable kdump
systemctl disable kdump.service

# Some Useradd config
echo "SHELL=/bin/sh
INACTIVE=30" > /etc/default/useradd
useradd -D -f 35 

# Disable CAD
rm /etc/init/control-alt-delete.override
rm /etc/init/control-alt-delete.conf
touch /etc/init/control-alt-delete.override
touch /etc/init/control-alt-delete.conf
sed -i "s/JobTimeoutAction=.*/JobTimeoutAction=none/gI" /usr/lib/systemd/system/control-alt-delete.target

# Lock and unlock users
for x in $(awk -F: '($3<1000)&&($1!="nobody"){print $1}' /etc/passwd)
do
usermod -L $x
done
for x in $(awk -F: '($3>=1000)&&($1!="nobody"){print $1}' /etc/passwd)
do
usermod -U $x
done
# Make unowned files owned by root
find / \( -nouser -o -nogroup \) -exec chown root:root {} \;


# Copy in sudoers
cp `pwd`/utils/sudoers /etc/sudoers
rm /etc/sudoers.d/*
echo "" > /etc/sudo.conf

# Add stickybit
find / -perm -o+w -exec chmod +t {} + 2>/dev/null

# configure shells
echo "
/bin/sh
/bin/bash
/usr/bin/bash
" > /etc/shells

# remove nologin
rm /etc/nologin 2>/dev/null

# Clean environment
echo "PATH='/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin'" > /etc/environment
cp /etc/environment /etc/environment.d/*

# Configure kerneloops
echo "
allow-submit = no
submit-url = http://oops.kernel.org/submitoops.php
log-file = /var/log/kern.log
submit-pipe = /usr/share/apport/kernel_oops
" > /etc/kerneloops.conf

# configure subuid/subgid
echo "" > /etc/subuid
#start=100000
#for u in $(cat /etc/passwd | grep -E "/bin/.*sh" | cut -d":" -f1 | sed s'/root//g' | xargs)
#do
#echo "$u:$start:65536" >> /etc/subuid
#start=$((start+65536))
#done
chmod 644 /etc/subuid
cp /etc/subuid /etc/subuid-
cp /etc/subuid /etc/subgid
cp /etc/subgid /etc/subgid-

# Configure overlayroot
echo "
overlayroot_cfgdisk=\"disabled\"
overlayroot=""
" > /etc/overlayroot.conf

# Set permission on yum repos
chmod -R 644 /etc/yum.repos.d
chown -R root:root /etc/yum.repos.d

# Configure keys


#Configure logrotate
echo "daily
rotate 28
create
dateext
include /etc/logrotate.d
" > /etc/logrotate.conf

# configure adduser/deluser
#cp `pwd`/utils/adduser.conf /etc/adduser.conf
#chmod 644 /etc/adduser.conf
#chown root:root /etc/adduser.conf
#cp `pwd`/utils/deluser.conf /etc/deluser.conf
#chmod 644 /etc/deluser.conf
#chown root:root /etc/deluser.conf
echo "SHELL=/bin/sh
INACTIVE=30" > /etc/default/useradd
useradd -D -f 35 

# Disable spyware
sed -i "s/enabled=1/enabled=0/gI" /etc/default/apport
sed -i "s/enabled=1/enabled=0/gI" /etc/default/whoopsie
sed -i "s/report_crashes=.*/report_crashes=0/gI" /etc/default/whoopsie
dnf remove tracker-miner-fs -y
dnf remove popularity-contest -y
dnf remove tracker -y
dnf remove tracker-extract
rm /etc/cron.daily/popularity-contest
sed -i "s/ENABLED=.*/ENABLED=0/gI" /etc/default/irqbalance
echo "enabled=0" > /etc/default/apport
echo "enabled=0" > /etc/default/whoopsie
echo "report_crashes=0" > /etc/default/whoopsie
echo "enabled=0" > /etc/default/irqbalance


#automatic upgrades
systemctl enable --now dnf-automatic.timer
echo "[commands]
apply_updates=True
" > /etc/dnf/automatic.conf

# Upgrade
#dnf upgrade --refresh -y

# Configure DNF
cp `pwd`/utils/dnf.conf /etc/dnf/dnf.conf

# Set crypto policies
update-crypto-policies --set FIPS
#fips-mode-setup --enable
#yum install dracut-fips
#yum install dracut-fips-aesni
#dracut -v -f
#sed -i "s/PRELINKING=.*/PRELINKING=no/gI" /etc/sysconfig/prelink
#prelink -u -a
#sed -i "s/GRUB_CMDLINE_LINUX=.*/GRUB_CMDLINE_LINUX=\"fips=0\"/gI" /etc/default/grub
# Set kernel parameters
#mv `pwd`/utils/kconfig /usr/lib/modules/$(uname -r)/config
grub2-mkconfig -o /boot/grub2/grub.cfg
systemctl daemon-reload

echo "Done"

