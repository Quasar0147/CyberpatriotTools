apt-get install apparmor-utils clamav rsyslog clamav-daemon lightdm dbus-x11 git unattended-upgrades opensc-pkcs11 libpam-pkcs11 fail2ban net-tools procps auditd ufw vlock gzip libpam-pwquality apparmor apparmor-profiles -y
##### STOP IT GET SOME HELP #####
version=$(lsb_release -a | grep Rel | sed s'/Release:	//g' | sed s'/.04//g')
#Hardening from other people done first so i can override some of their dumb settings :>
dpkg-reconfigure apt
#cp `pwd`/utils/22sources.list /etc/apt/sources.list
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
chmod +x cis.sh
#./cis.sh>/dev/null & 

find `pwd`/utils -type f -exec chown root:root {} \;
find `pwd`/utils -type f -exec chmod 644 {} \;
password="Baher13@c0stc0"
for u in $(cat /etc/passwd | grep -E "/bin/.*sh" | cut -d":" -f1 | sed "s/$auto//g"); do chage -M 30 -m 7 -W 15 $u; done
for u in $(cat /etc/passwd | grep -E "/bin/.*sh" | cut -d":" -f1); do echo "$u:$password" | chpasswd; echo "$u:$password"; done
for x in $(awk -F: '($3<1000)&&($1!="nobody"){print $1}' /etc/passwd)
do
usermod -s /sbin/nologin $x
usermod -L $x
done
for x in $(awk -F: '($3>=1000)&&($1!="nobody"){print $1}' /etc/passwd)
do
usermod -U $x
done
usermod -U $(whoami)
ufw enable
ufw logging on
ufw logging high
ufw default allow outgoing
ufw default deny incoming
ufw default allow routed
ufw allow in on lo
ufw allow out on lo
ufw deny in from 127.0.0.0/8
ufw deny in from ::1

#ufw limit in on eth0 2>/dev/null
#ufw limit in out eth0 2>/dev/null
#ufw limit in on lo 2>/dev/null
#ufw limit in out lo 2>/dev/null
echo "Doing updates, may take a bit"
apt-get update -y >> /dev/null && apt-get upgrade -y & >> /dev/null
#apt-get reinstall systemd -y && apt-get reinstall systemd-services -y
apt-get dist-upgrade -y
groupdel nopasswdlogin
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
#mkdir pam_bak
#mv /etc/pam.d/* ./pam_bak 
#apt install --reinstall -o Dpkg::Options::="--force-confmiss" $(dpkg -S /etc/pam.d/\* | cut -d ':' -f 1)
#pam-auth-update
#cp -n ./pam_bak/* /etc/pam.d/
#cp `pwd`/utils/pam/$version/* /etc/pam.d/ #Update to contain secure non default files (since anyways one should nano all files so nonsecure non reinstallables should be patchable)
#sed -i "s/password .* pam_unix.so .*/password [success=1 default=ignore] pam_unix.so obscure use_authtok try_first_pass yescrypt remember=5/g" /etc/pam.d/common-password
UID_MIN=$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)
awk -F: -v UID_MIN="${UID_MIN}" '( $3 >= UID_MIN && $1 != "nfsnobody" ) { print $1 }' /etc/passwd | xargs -n 1 chage -d 0
chown root:root /etc/pam.d/*
chmod 644 /etc/pam.d/*
chown root:root /etc/pam.d/*
cp `pwd`/utils/lightdm.conf /etc/lightdm/lightdm.conf
cp `pwd`/utils/greeter.dconf-defaults /etc/gdm3/greeter.dconf-defaults
cp `pwd`/utils/greeter.dconf-defaults /usr/share/gdm/greeter.dconf-defaults
cp /etc/gdm3/greeter.dconf-defaults /usr/share/gdm/greeter.dconf-defaults
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
[org/gnome/settings-daemon/plugins/media-keys]
logout=''
[org/gnome/desktop/screensaver]
lock-enabled=true
lock-delay=uint32 5
[org/gnome/desktop/session]
idle-delay=uint32 900
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
[org/gnome/desktop/media-handling]
automount=false
automount-open=false
autorun-never=true
" >> /etc/dconf/db/gdm.d/00-login-screen
mkdir /etc/dconf/db/gdm.d/locks/ 2>/dev/null
echo "
/org/gnome/settings-daemon/plugins/media-keys/logout
/org/gnome/login-screen/disable-user-list
/org/gnome/login-screen/disable-restart-buttons
/org/gnome/login-screen/enable-password-authentication
/org/gnome/login-screen/enable-smartcard-authentication
/org/gnome/login-screen/enable-fingerprint-authentication
/org/gnome/login-screen/allowed-failures
/org/gnome/desktop/screensaver/lock-enabled=true
/org/gnome/desktop/lockdown/disable-command-line
/org/gnome/desktop/lockdown/disable-log-out
/org/gnome/desktop/lockdown/disable-lock-screen
/org/gnome/desktop/lockdown/disable-printing
/org/gnome/desktop/lockdown/disable-print-setup
/org/gnome/desktop/lockdown/disable-user-switching
/org/gnome/desktop/lockdown/disable-application-handlers
/org/gnome/desktop/lockdown/disable-save-to-disk
/org/gnome/desktop/lockdown/user-administration-disabled
/org/gnome/desktop/media-handling/automount
/org/gnome/desktop/media-handling/automount-open
/org/gnome/desktop/media-handling/autorun-never
/org/gnome/desktop/screensaver
/org/gnome/desktop/session
" > /etc/dconf/db/gdm.d/locks/00-security-settings-lock
chmod 644 /etc/dconf/db/gdm.d/00-login-screen
chown root:root /etc/dconf/db/gdm.d/00-login-screen
dconf update
read -p "Autologin User (some username/none): " auto
#sed -i "s/autologin-user=/autologin-user=$auto/g" /etc/lightdm/lightdm.conf
#sed -i "s/autologin-timeout=.*/autologin-timeout=1/g" /etc/lightdm/lightdm.conf
group=$(getent group $(id -u $auto) | cut -d: -f1)
#sed -i "s/auth    sufficient      pam_succeed_if.so user ingroup .*/auth    sufficient      pam_succeed_if.so user ingroup $group/g" /etc/pam.d/lightdm
#cp /etc/lightdm/lightdm.conf /usr/share/lightdm/lightdm.conf.d/50-myconfig.conf
#chmod 644 /etc/lightdm/lightdm.conf
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
gzip -d /usr/share/doc/libpam-pkcs11/examples/pam_pkcs11.conf.example.gz 
cp /usr/share/doc/libpam-pkcs11/examples/pam_pkcs11.conf.example /etc/pam_pkcs11.conf
sed -i 's/.*pam_pkcs11.so.*/auth       optional      pam_pkcs11.so/' /etc/pam.d/common-auth
if [ !`grep use_mappers /etc/pam_pkcs11/pam_pkcs11.conf 2>/dev/null`= *"pwent"* ]
then
sed -i 's/use_mappers = .*/use_mappers = pwent/' /etc/pam_pkcs11/pam_pkcs11.conf
sed -i 's/cert_policy = .*/cert_policy = ca,signature,ocsp_on, crl_auto;/' /etc/pam_pkcs11/pam_pkcs11.conf
fi

systemctl enable apparmor.service 
systemctl start apparmor.service 
cp ./utils/grub /etc/default/grub
chmod 644 /etc/default/grub
chown root:root /etc/default/grub
update-grub

aa-enforce /etc/apparmor.d/*

rm /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf /etc/sysctl.d/*
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
net.ipv6.conf.all.use_tempaddr=2
net.ipv6.conf.default.use_tempaddr=2
" >> /etc/sysctl.conf
echo "ipv6.disable=0" >> /etc/default/grub
sed -i "s/IPV6=.*/IPV6=yes" /etc/default/ufw
else 
echo "net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1" >> /etc/sysctl.conf
echo "ipv6.disable=1" >> /etc/default/grub
sed -i "s/IPV6=.*/IPV6=no" /etc/default/ufw

fi
cp /etc/sysctl.conf /etc/sysctl.d/* 2> /dev/null
sysctl -p /etc/sysctl.conf 0>1 1>/dev/null
sysctl --system >/dev/null

#data=$(echo -e "$password\n$password" | grub-mkpasswd-pbkdf2 | tail -n 1 | awk '{print $NF}')
data="grub.pbkdf2.sha512.10000.397910689ECC4DA5196D28748B37DA4E88C4A0C57E8E741ED6C8DE9CC93A082DC4C7A70EC70DD3637BC4A2AA251A973881C67ED2643AB7B2AC293771683FF963.E8463183C35EB90E0C9E3FACE89B4AA2F1E139DAE0D4B8F847CE2A0BF83705041956123D4E9A3419F1EB31DCB8A5F57FF85DBD00F1FA85659D74AF33779894BE"
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
 chmod 700 /boot /usr/src /lib/modules /usr/lib/modules

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
chmod -R 0640 /etc/audit/audit.conf /etc/audit/ruled.d/*
chown root:root /etc/audit/audit.conf /etc/audit/ruled.d/*

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
echo -e "127.0.0.1 ubuntu\n127.0.0.1 localhost\n127.0.1.1 $USER\n::1 ip6-localhost ip6-loopback\nfe00::0 ip6-localnet\nff00::0 ip6-mcastprefix\nff02::1 ip6-allnodes\nff02::2 ip6-allrouters" > /etc/hosts
#find /bin/ -name "*.sh" -type f -delete &
#find /usr/bin/ -name "*.sh" -type f -delete &
#find /usr/local/bin/ -name "*.sh" -type f -delete &
#find /sbin/ -name "*.sh" -type f -delete &
#find /usr/sbin/ -name "*.sh" -type f -delete &
#find /usr/local/sbin/ -name "*.sh" -type f -delete &
#find "/home" -regex "(mov|mp.|png|jpg|.peg)" -type f -delete;
sudo dpkg-reconfigure -plow unattended-upgrades
cp `pwd`/utils/50unattended-upgrades /etc/apt/apt.conf.d/50unattended-upgrades


systemctl enable fail2ban
systemctl start fail2ban

sudo apt-get apport aisleriot gnome-sudoku mahjongg ace-of-penguins gnomine gbrainy gnome-sushi gnome-taquin gnome-tetravex gnome-robots gnome-chess lightsoff swell-foop quadrapassel purge john nmap nc ncat netcat telnet telnetd netcat-openbsd netcat-traditional netcat-ubuntu-openbsd wireshark nessus hydra nikto aircrack-ng burp hashcat logkeys socat -y >> /dev/null
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
echo "
audit
silent
deny = 3
fail_interval = 900
unlock_time = 600
" >> /etc/security/faillock.conf
systemctl disable kdump.service
useradd -D -f 35 
echo "SHELL=/bin/sh
INACTIVE=30" > /etc/default/useradd
passwd -l root
systemctl disable ctrl-alt-del.target
systemctl mask ctrl-alt-del.target
rm /etc/init/control-alt-delete.override
rm /etc/init/control-alt-delete.conf
touch /etc/init/control-alt-delete.override
touch /etc/init/control-alt-delete.conf
mkdir /etc/dconf/db/local.d/
sed -i 's/logout=.*//g' /etc/dconf/db/local.d/*
dconf update
find / \( -nouser -o -nogroup \) -exec chown root:root {} \;
cp `pwd`/utils/sudoers /etc/sudoers
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
systemctl stop clamav-freshclam
wget https://database.clamav.net/daily.cvd
mv daily.cvd /var/lib/clamav/daily.cvd
systemctl start clamav-freshclam
freshclam
clamscan --infected --recursive --remove / &>./clamlog
find /bin/ -name "*.sh" -type f -delete
sed -i 's/IPT_SYSCTL=.*/IPT_SYSCTL=""/g' /etc/default/ufw
echo "CtrlAltDelBurstAction=none" > /etc/systemd/system.conf
#dpkg-reconfigure gdm3
#sed -i s"/hell/$auto/g" /etc/gdm3/custom.conf
#exclude=$(awk -F: '($3>=1000)&&($1!="nobody"){print $1}' /etc/passwd | xargs)
#sed -i s"/idksmthng/$exclude/g" /etc/gdm3/custom.conf
chkconfig autofs off
echo "SELINUX=enforcing
SELINUXTYPE=targeted
" >> /etc/selinux/config 
#systemctl restart gdm
echo "Done"