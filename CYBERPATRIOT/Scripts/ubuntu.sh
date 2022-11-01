##### STOP IT GET SOME HELP #####
# This script is for Ubuntu 20.04 LTS
version=$(cat /etc/os-release | head -n 6 | tail -n 1 | cut -c13-14)
if [ $version = "20" ]
then
version="20"
else
version="22"
fi
#Hardening from other people done first so i can override some of their dumb settings :>
dpkg-reconfigure apt
apt-get -y install git net-tools procps >> /dev/null
git clone https://github.com/konstruktoid/hardening.git
cp `pwd`/utils/ubuntu.cfg hardening/ubuntu.cfg
cd hardening
bash ubuntu.sh &
cd ..
echo "
wget https://github.com/ComplianceAsCode/content/releases/download/v0.1.64/scap-security-guide-0.1.64-oval-5.10.zip >> /dev/null
unzip scap-security-guide-0.1.64-oval-5.10.zip >> /dev/null
apt-get install libopenscap8 -y >> /dev/null
apt-get install wget -y >> /dev/null
path=`realpath $(find .. -name \"ssg-ubuntu\"$version\"04-ds.xml\" | head -n 1)`
oscap xccdf eval --remediate --profile xccdf_org.ssgproject.content_profile_cis_level2_workstation --results ssg-cis-oscap.xml \$path >> /dev/null
" >> cis.sh
if [ $version = "20" ]
then
echo "
oscap xccdf eval --remediate --profile xccdf_org.ssgproject.content_profile_stig --results ssg-stig-oscap.xml scap-security-guide-0.1.64-oval-5.10/ssg-ubuntu2004-ds.xml
" >> cis.sh
fi
chmod +x cis.sh
#./cis.sh>/dev/null & 

find `pwd`/utils -type f -exec chown root:root {} \;
find `pwd`/utils -type f -exec chmod 644 {} \;
password="Baher13@c0stc0"
for u in $(cat /etc/passwd | grep -E "/bin/.*sh" | cut -d":" -f1); do echo "$u:$password" | chpasswd; echo "$u:$password"; done
for u in $(cat /etc/passwd | grep -E "/bin/.*sh" | cut -d":" -f1); do chage -M 30 -m 7 -W 15 $u; done
apt-get install ufw -y >> /dev/null
ufw enable
ufw logging on
ufw logging high
ufw default allow outgoing
ufw default deny incoming
ufw default allow routed
#ufw limit in on eth0 2>/dev/null
#ufw limit in out eth0 2>/dev/null
#ufw limit in on lo 2>/dev/null
#ufw limit in out lo 2>/dev/null
echo "Doing updates, may take a bit"
apt-get update -y >> /dev/null && apt-get upgrade & -y >> /dev/null
apt-get reinstall systemd -y && apt-get reinstall systemd-services -y
apt-get dist-upgrade -y
groupdel nopasswdlogin
apt-get install lightdm -y >> /dev/null
apt-get install net-tools -y >> /dev/null
apt-get install auditd -y >> /dev/null
systemctl enable auditd
systemctl start auditd
apt-get install apparmor-utils -y >> /dev/null
systemctl enable auditd
systemctl start auditd
if [ -f /etc/ssh/sshd_config ]; then
    cp `pwd`/utils/sshd_config /etc/ssh/sshd_config
    echo "DENY_THRESHOLD_INVALID = 5
    DENY_THRESHOLD_VALID = 10
    DENY_THRESHOLD_ROOT = 1
    " > /etc/denyhosts.conf
    systemctl restart denyhosts
    systemctl enable denyhosts
    systemctl restart ssh
    systemctl enable ssh
fi
for u in $(cat /etc/passwd | grep -E "/bin/.*sh" | cut -d":" -f1 | sed s'/root//g' | xargs); do sed -i "/^AllowUser/ s/$/ $u /" /etc/ssh/sshd_config; done
cp `pwd`/utils/pam/* /etc/pam.d/
chown root:root /etc/pam.d/*
chmod 644 /etc/pam.d/*
chown root:root /etc/pam.d/*
cp `pwd`/utils/lightdm.conf /etc/lightdm/lightdm.conf
cp `pwd`/utils/greeter.dconf-defaults /etc/gdm3/greeter.dconf-defaults
cp `pwd`/utils/gdm3.conf /etc/gdm3/custom.conf
echo "user-db:user
system-db:gdm
file-db:/usr/share/gdm/greeter-dconf-defaults
" >> /etc/dconf/profile/gdm
chmod 644 /etc/dconf/profile/gdm
chown root:root /etc/dconf/profile/gdm
rm /etc/dconf/db/gdm.d/* 2>/dev/null
mkdir /etc/dconf/db/gdm.d/ 2>/dev/null
echo "[org/gnome/login-screen]
disable-user-list=true
disable-restart-buttons=true
enable-password-authentication=true
enable-smartcard-authentication=false
enable-fingerprint-authentication=false
allowed-failures=3
[org/gnome/desktop/screensaver]
lock-enabled=true
[org/gnome/desktop/lockdown]
disable-command-line=true
disable-log-out=true
disable-printing=true
disable-lock-screen=true
disable-print-setup=true
disable-user-switching=true
disable-application-handlers=true
disable-save-to-disk=true
user-administration-disabled=true
" >> /etc/dconf/db/gdm.d/00-login-screen
chmod 644 /etc/dconf/db/gdm.d/00-login-screen
chown root:root /etc/dconf/db/gdm.d/00-login-screen
dconf update

while :;
    do
    read -p "Autologin User (some username/none): " a
    if [ $a = "root" ]; then
        echo "root is not allowed for autologin"
    elif [ $(cat /etc/passwd | grep -E "/bin/.*sh" | cut -d: -f1) != "*$a*" ];
    then
        echo "User does not exist"
    elif [ $a == "none" ]; then
        break
    else 
        sed -i "s/autologin-user=/autologin-user=$a/g" /etc/lightdm/lightdm.conf
        sed -i "s/autologin-timeout=.*/autologin-timeout=1/g" /etc/lightdm/lightdm.conf
        group=$(getent group $(id -u $a) | cut -d: -f1)
        sed -i "s/*actualhell/$group/g" /etc/pam.d/lightdm
        break
    fi
done
cp /etc/lightdm/lightdm.conf /usr/share/lightdm/lightdm.conf.d/50-myconfig.conf
chmod 644 /etc/lightdm/lightdm.conf
apt-get install libpam-pwquality -y >> /dev/null
rm /etc/security/pwquality.conf
echo "difok=8
minlen=14
dcredit=-1
ucredit=-1
lcredit=-1
ocredit=-1
minclass=4
maxrepeat=2
gecoscheck=1
dictcheck=1
maxsequence=4
maxclassrepeat=4
usercheck=1
enforcing=1
enforce_for_root=1" >> /etc/security/pwquality.conf
sed -i 's/umask .*//' /etc/profile
echo "umask 027" >> /etc/profile
sed -i 's/umask .*//' /etc/login.defs
echo "umask 027" >> /etc/login.defs

cp /etc/bash.bashrc /home/*/.bashrc
cp /etc/bash.bashrc /root/.bashrc
chmod 644 /home/*/.bashrc
chmod 644 /root/.bashrc
cp `pwd`/utils/login.defs /etc/login.defs
sudo apt-get install vlock
sudo apt-get install gzip
gzip -d /usr/share/doc/libpam-pkcs11/examples/pam_pkcs11.conf.example.gz 
cp /usr/share/doc/libpam-pkcs11/examples/pam_pkcs11.conf.example /etc/pam_pkcs11.conf
sed -i 's/.*pam_pkcs11.so.*/auth       optional      pam_pkcs11.so/' /etc/pam.d/common-auth
if [[ `grep use_mappers /etc/pam_pkcs11/pam_pkcs11.conf 2>/dev/null` != *"pwent"* ]]
then
sed -i 's/use_mappers = .*/use_mappers = pwent/' /etc/pam_pkcs11/pam_pkcs11.conf
sed -i 's/cert_policy = .*/cert_policy = ca,signature,ocsp_on, crl_auto;/' /etc/pam_pkcs11/pam_pkcs11.conf
fi

apt-get install apparmor apparmor-profiles -y  -qq > /dev/null
systemctl enable apparmor.service 
systemctl start apparmor.service 
cp ./utils/grub /etc/default/grub
chmod 644 /etc/default/grub
chown root:root /etc/default/grub
update-grub
aa-enforce /etc/apparmor.d/*

cp `pwd`/utils/sysctl.conf /etc/sysctl.conf
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
" >> /etc/sysctl.conf
echo "ipv6.disable=0" >> /etc/default/grub
else 
echo "net.ipv6.conf.all.disable_ipv6=1" >> /etc/sysctl.conf
echo "ipv6.disable=1" >> /etc/default/grub
fi
cp /etc/sysctl.conf /etc/sysctl.d/* 2> /dev/null
sysctl -p /etc/sysctl.conf 0>1 1>/dev/null
sysctl --system >/dev/null

data=$(echo -e "$password\n$password" | grub-mkpasswd-pbkdf2 | tail -n 1 | awk '{print $NF}')
echo "cat <<EOF
set superusers='root'
password pbkdf2 root '"$data"'
EOF" >> /etc/grub.d/00_header
sudo chmod 744 /etc/grub.d/00_header
sudo update-grub

sudo chmod 744 /etc/default/grub
sudo chown root:root /boot/grub/grub.cfg 2>/dev/null
sudo chmod 744 /boot/grub/grub.cfg 2>/dev/null
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
chown root:root /etc/pam.d/common-password /etc/pam.d/common-auth /etc/pam.d/login /etc/login.defs /etc/security/pwquality.conf
chmod 0644 /etc/pam.d/common-password /etc/pam.d/common-auth /etc/pam.d/login /etc/login.defs /etc/security/pwquality.conf
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
chown root:syslog /var/log
find /var/log -perm /137 -type f -exec chmod 640 '{}' \;
find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin ! -user root -type f -exec  -c chown root:root '{}' +;
 
apt-get install rsyslog
for u in $(cat /etc/passwd | grep -E "/bin/.*sh" | cut -d":" -f1); do passwd -l $u; done
auditctl -e 1
cp `pwd`/utils/audit.rules /etc/audit/rules.d/audit.rules
augenrules --load
echo "* hard core" > /etc/security/limits.conf
echo "* hard maxlogins 10" >> /etc/security/limits.conf
sudo chmod 744 /etc/security/limits.conf
sudo chmod 600 /etc/ssh/*key 2>/dev/null
sudo chmod 640 /etc/ssh/*key.pub 2>/dev/null
sudo chmod 640 /etc/ssh/*key-cert.pub 2>/dev/null
chmod 0640 /var/log/syslog
chown syslog /var/log/syslog
for x in "dccp sctp tipc rds"; do sudo modprobe -n -v $x; echo "install $x /bin/true" >> /etc/modprobe.d/ubuntu.conf; done
sudo chmod 744 /etc/modprobe.d/ubuntu.conf 2>/dev/null
echo "auditd_max_log_file=16384
auditd_space_left_action=email
auditd_action_mail_acct=root
auditd_admin_space_left_action=halt
auditd_max_log_file_action=keep_logs
auditd_disk_full_action = HALT 
auditd_log_file = /var/log/audit/audit.log 
auditd_log_group=root
auditd_local_events: 'yes'
" >> /etc/audit/auditd.conf
chmod 600 /var/log/audit/audit.log
chown root:root /var/log/audit/audit.log
sudo chmod -R  g-w,o-rwx /var/log/audit
chmod -R 0640 /etc/audit/audit*.{rules,conf} /etc/audit/rules.d/*
chown root:root /etc/audit/audit*.{rules,conf} /etc/audit/rules.d/*

systemctl kill auditd -s SIGHUP
sudo chmod 744 /etc/audit/auditd.conf
systemctl restart auditd
crontab -r
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
echo > /etc/rc.local
echo -e "127.0.0.1 ubuntu\n127.0.0.1 localhost\n127.0.1.1 $USER\n::1 ip6-localhost ip6-loopback\nfe00::0 ip6-localnet\nff00::0 ip6-mcastprefix\nff02::1 ip6-allnodes\nff02::2 ip6-allrouters" >> /etc/hosts
find /bin/ -name "*.sh" -type f -delete &
find /usr/bin/ -name "*.sh" -type f -delete &
find /usr/local/bin/ -name "*.sh" -type f -delete &
find /sbin/ -name "*.sh" -type f -delete &
find /usr/sbin/ -name "*.sh" -type f -delete &
find /usr/local/sbin/ -name "*.sh" -type f -delete &
find "/home" -regex "(mov|mp.|png|jpg|.peg)" -type f -delete; done; done
apt-get purge aisleriot gnome-sudoku mahjongg ace-of-penguins gnomine gbrainy gnome-sushi gnome-taquin gnome-tetravex gnome-robots gnome-chess lightsoff swell-foop quadrapassel >> /dev/null && sudo apt-get autoremove >> /dev/null
apt-get install unattended-upgrades -y >> /dev/null
sudo dpkg-reconfigure -plow unattended-upgrades
cp `pwd`/utils/50unattended-upgrades /etc/apt/apt.conf.d/50unattended-upgrades


apt-get install -y fail2ban >> /dev/null
systemctl enable fail2ban
systemctl start fail2ban

sudo apt-get purge john nmap nc ncat netcat netcat-openbsd netcat-traditional netcat-ubuntu-openbsd wireshark nessus hydra nikto aircrack-ng burp hashcat logkeys socat -y >> /dev/null
for u in $(cat /etc/passwd | grep -E "/bin/.*sh" | cut -d: -f1); do for x in $(cat /home/*/.mozilla/firefox/profiles.ini | grep "Path=" | cut -c6-1000 | xargs); do cp utils/user.js /home/$u/.mozilla/firefox/$x/user.js 2>/dev/null; chmod 644 /home/$u/.mozilla/firefox/$x/user.js ; done; done
sed s'/user_pref(/pref(/g' utils/user.js > /etc/firefox/syspref.js

cp `pwd`/utils/bash.bashrc /etc/bash.bashrc
cp `pwd`/utils/profile /etc/profile
chmod 644 /etc/profile
cp /etc/profile /home/*/.profile
cp /etc/profile /root/.profile
chmod 644 /home/*/.profile
chmod 644 /root/.profile
chmod 644 /etc/bash.bashrc
#echo "console" > /etc/securetty
echo "" > /etc/securetty
apt-get install opensc-pkcs11 -y >> /dev/null
apt-get install libpam-pkcs11 -y >> /dev/null
echo "
audit
silent
deny = 3
fail_interval = 900
unlock_time = 0
" >> /etc/security/faillock.conf
systemctl disable kdump.service
apt-get install mfetp
useradd -D -f 35 
echo "SHELL=/bin/sh
INACTIVE=30" > /etc/default/useradd
passwd -l root
apt-get remove telnetd -y
apt-get remove telnet -y
systemctl disable ctrl-alt-del.target
systemctl mask ctrl-alt-del.target
rm /etc/init/control-alt-delete.override
rm /etc/init/control-alt-delete.conf
touch /etc/init/control-alt-delete.override
touch /etc/init/control-alt-delete.conf
mkdir /etc/dconf/db/local.d/
sed -i 's/logout=.*//g' /etc/dconf/db/local.d/*
echo "
[org/gnome/settings-daemon/plugins/media-keys]
logout=''
" >> /etc/dconf/db/local.d/00-disable-CAD
dconf update
for x in $(awk -F: '($3<1000)&&($1!="nobody"){print $1}' /etc/passwd)
do
usermod -s /sbin/nologin $x
usermod -L $x
done
for x in $(awk -F: '($3>=1000)&&($1!="nobody"){print $1}' /etc/passwd)
do
usermod -U $x
done
for x in $(cut -d: -f1,3 /etc/passwd | egrep ':[0]{1}$' | cut -d: -f1 | sed s'/root//g')
do
echo "Deleting hidden user [$x]"
userdel $x
done
find / \( -nouser -o -nogroup \) -exec chown root:root {} \;
echo "
Defaults	env_reset
Defaults	secure_path=\"/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\"
root	    ALL=(ALL:ALL) ALL
%admin      ALL=(ALL) ALL
%sudo	    ALL=(ALL:ALL) ALL
" > /etc/sudoers
rm /etc/sudoers.d/*
systemctl daemon-reload
for u in $(cat /etc/passwd | grep -E "/bin/.*sh" | cut -d: -f1); do 
    crontab -u $u -r >> /dev/null
done
find / -perm -o+w -exec chmod +t {} + 2>/dev/null
echo "
/bin/sh
/bin/bash
/usr/bin/bash
" > /etc/shells
gsettings set org.gnome.desktop.screensaver lock-enabled true
rm /etc/nologin 2>/dev/null
echo "PATH='/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin'" > /etc/environment
cp /etc/environment /etc/environment.d/*
echo "
allow-submit = no
submit-url = http://oops.kernel.org/submitoops.php
log-file = /var/log/kern.log
submit-pipe = /usr/share/apport/kernel_oops
" > /etc/kerneloops.conf
echo "" > /etc/subuid
start=100000
for u in $(cat /etc/passwd | grep -E "/bin/.*sh" | cut -d":" -f1 | sed s'/root//g' | xargs)
do
echo "$u:$start:65536" >> /etc/subuid
start=$((start+65536))
done
chmod 644 /etc/subuid
cp /etc/subuid /etc/subuid-
cp /etc/subuid /etc/subgid
cp /etc/subgid /etc/subgid-
echo "
overlayroot_cfgdisk=\"disabled\"
overlayroot=""
" > /etc/overlayroot.conf
echo "" > /etc/pam.conf
apt-get install clamav clamav-daemon -y >> /dev/null
systemctl stop clamav-freshclam
wget https://database.clamav.net/daily.cvd -O /var/lib/clamav/daily.cvd
freshclam
systemctl start clamav-freshclam
clamscan --infected --recursive --remove / &>./clamlog
find /bin/ -name "*.sh" -type f -delete
dpkg-reconfigure lightdm
systemctl restart gdm


