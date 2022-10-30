#!/usr/bin/bash
1.1.1(){
    echo "Remove unneccessary file systems (automated)"
    echo "Will remove: $FileSystems"
    FileSystems="cramfs freevxfs jffs2 hfs hfsplus squashfs udf"
    for system in $FileSystems
    do
    if [ `modprobe -n -v $system | grep -E "($system|install)"` != "install /bin/true" || `lsmod | grep $system` != "" ]
    then
    echo "install $system /bin/true" > /etc/modprobe.d/$system.conf
    rmmod $system
    fi
    done
}
1.1.2-21(){
    echo "Ensuring /tmp and /dev/shm is mounted to tmpfs with correct options, and tmp var is correctly mounted"
    a=`findmnt -n /tmp`
    if [ "$a" != "/tmp tmpfs tmpfs rw,nosuid,nodev,noexec" ]
    then
        echo "tmpfs /tmp tmpfs defaults,rw,nosuid,nodev,noexec,relatime 0 0" >> /etc/fstab
        cp -v /usr/share/systemd/tmp.mount /etc/systemd/system/
        echo "[Mount]" >> /etc/systemd/system/tmp.mount
        echo "What=tmpfs" >> /etc/systemd/system/tmp.mount
        echo "Where=/tmp" >> /etc/systemd/system/tmp.mount
        echo "Type=tmpfs Options=mode=1777,strictatime,nosuid,nodev,noexec" >> /etc/systemd/system/tmp.mount
        mount -o remount,nodev,nosuid,noexec /tmp
        systemctl daemon-reload
        systemctl --now enable tmp.mount
        systemctl restart tmp.mount

    fi
    a=`findmnt -n /dev/shm`
    if [ "$a" != "/dev/shm tmpfs tmpfs rw,nosuid,nodev,noexec" ]
    then
        echo "tmpfs /dev/shm tmpfs defaults,noexec,nodev,nosuid,seclabel 0 0" >> /etc/fstab
        mount -o remount,noexec,nodev,nosuid /dev/shm
    fi
    a=`findmnt /var`
    devicename=`echo "$a" | awk '{print $2 }'`
    fstypename=`echo "$a" | awk '{print $3 }'`
    if [ "$devicename" == "" ]
    then
        read -p "Could not aquire devicename, manually input (found in /etc/fstab): " devicename
    fi
    if [ "$fstypename" == "" ]
    then
        read -p "Could not aquire fstypename, manually input (found in /etc/fstab): " fstypename
    fi
    if [ "$a" != "/var $devicename $fstypename rw,relatime,attr2,inode64,noquota" ]
    then
        echo "/var $devicename $fstypename rw,relatime,attr2,inode64,noquota" >> /etc/fstab
    fi
    a=`findmnt /var/tmp`
    devicename=`echo "$a" | awk '{print $2 }'`
    fstypename=`echo "$a" | awk '{print $3 }'`
    if [ "$devicename" == "" ]
    then
        read -p "Could not aquire devicename, manually input (found in /etc/fstab): " devicename
    fi
    if [ "$fstypename" == "" ]
    then
        read -p "Could not aquire fstypename, manually input (found in /etc/fstab): " fstypename
    fi
    if [ "$a" != "/var/tmp $devicename $fstypename rw,relatime,attr2,inode64,noquota" ]
    then
        echo "/var/tmp $devicename $fstypename rw,relatime,attr2,inode64,noquota" >> /etc/fstab
    fi
    a=`findmnt /var/log`
    devicename=`echo "$a" | awk '{print $2 }'`
    fstypename=`echo "$a" | awk '{print $3 }'`
    if [ "$devicename" == "" ]
    then
        read -p "Could not aquire devicename, manually input (found in /etc/fstab): " devicename
    fi
    if [ "$fstypename" == "" ]
    then
        read -p "Could not aquire fstypename, manually input (found in /etc/fstab): " fstypename
    fi
    if [ "$a" != "/var/log $devicename $fstypename rw,relatime,attr2,inode64,noquota" ]
    then
        echo "/var/log $devicename $fstypename rw,relatime,attr2,inode64,noquota" >> /etc/fstab
    fi
    a=`findmnt /var/log/audit`
    devicename=`echo "$a" | awk '{print $2 }'`
    fstypename=`echo "$a" | awk '{print $3 }'`
    if [ "$devicename" == "" ]
    then
        read -p "Could not aquire devicename, manually input (found in /etc/fstab): " devicename
    fi
    if [ "$fstypename" == "" ]
    then
        read -p "Could not aquire fstypename, manually input (found in /etc/fstab): " fstypename
    fi
    if [ "$a" != "/var/log $devicename $fstypename rw,relatime,attr2,inode64,noquota" ]
    then
        echo "/var/log/audit $devicename $fstypename rw,relatime,attr2,inode64,noquota" >> /etc/fstab
    fi
    a=`findmnt /home`
    devicename=`echo "$a" | awk '{print $2 }'`
    fstypename=`echo "$a" | awk '{print $3 }'`
    if [ "$devicename" == "" ]
    then
        read -p "Could not aquire devicename, manually input (found in /etc/fstab): " devicename
    fi
    if [ "$fstypename" == "" ]
    then
        read -p "Could not aquire fstypename, manually input (found in /etc/fstab): " fstypename
    fi
    if [ "$a" != "/home $devicename $fstypename rw,relatime,attr2,inode64,noquota,nodev" ]
    then
        echo "/home $devicename $fstypename rw,relatime,attr2,inode64,noquota,nodev" >> /etc/fstab
        mount -o remount,nodev /home
    fi
    wantedoptions="nodev noexec nosuid"
    for wantedopt in $wantedoptions
    do
        for x in `mount`
        do
            filename=`echo "$x" | awk '{print $1 }'`
            options=`echo "$x" | awk '{print $4 }'`
            if grep -q "$wantedopt" <<< "$options"
            then
                echo ""
            else
                if grep -q ")" <<< "$filename"
                then
                    echo ""
                else
                    echo "$filename failed $wantedopt checking"
                fi
            fi
        done
    done
    read -p "Proceed to nano [y/n]" a
    if [ "$a" == "y" ]
    then
        nano /etc/fstab
    fi
}
1.1.22(){
    echo "Adding sticky bits to all world writable"
    df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type d \( -perm -0002 -a ! -perm -1000 \) 2>/dev/null | xargs -I '{}' chmod a+t '{}'
}
1.1.23(){
    echo "Checking for autofs"
    if [ `systemctl is-enabled autofs` != "disabled" || `dpkg -s autofs` != "package \`autofs\` is not installed" ]
    then
    systemctl --now disable autofs
    apt purge autofs
    fi
}
1.1.24(){
    if [ `modprobe -n -v usb-storage` != "install /bin/true" || `lsmod | grep usb-storage` != "" ]
    then
        echo "lsmod | grep usb-storage" >> /etc/modprobe.d/usb_storage.conf
        rmmod usb-storage
    fi
}
1.1(){
    1.1.1
    1.1.2-21
    1.1.22
    1.1.23
    1.1.24
}
#####################################################
##############Above meant to NOT be run##############
#####################################################
1.3(){
    apt-cache policy
    read -p "Is the above ok? (Manual fix otherwise)"
    echo "deb http://archive.ubuntu.com/ubuntu/ focal main restricted universe multiverse" > /etc/apt/sources.list
    echo "deb-src http://archive.ubuntu.com/ubuntu/ focal main restricted universe multiverse" >> /etc/apt/sources.list
    echo "deb http://archive.ubuntu.com/ubuntu/ focal-updates main restricted universe multiverse" >> /etc/apt/sources.list
    echo "deb-src http://archive.ubuntu.com/ubuntu/ focal-updates main restricted universe multiverse" >> /etc/apt/sources.list
    echo "deb http://archive.ubuntu.com/ubuntu/ focal-security main restricted universe multiverse" >> /etc/apt/sources.list
    echo "deb-src http://archive.ubuntu.com/ubuntu/ focal-security main restricted universe multiverse" >> /etc/apt/sources.list
    echo "deb http://archive.ubuntu.com/ubuntu/ focal-backports main restricted universe multiverse" >> /etc/apt/sources.list
    echo "deb-src http://archive.ubuntu.com/ubuntu/ focal-backports main restricted universe multiverse" >> /etc/apt/sources.list
    echo "deb http://archive.canonical.com/ubuntu focal partner" >> /etc/apt/sources.list
    echo "deb-src http://archive.canonical.com/ubuntu focal partner" >> /etc/apt/sources.list
    dpkg-reconfigure apt
    apt install aide aide-common
    aideinit
    mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
    echo "0 5 * * * /usr/bin/aide.wrapper --config /etc/aide/aide.conf --check" >> /tmp/crontab.TCVYaD/crontab
    echo "[Unit]" >> /etc/systemd/system/aidecheck.service
    echo "Description=Aide Check" >> /etc/systemd/system/aidecheck.service
    echo "[Service]" >> /etc/systemd/system/aidecheck.service
    echo "Type=simple" >> /etc/systemd/system/aidecheck.service
    echo "ExecStart=/usr/bin/aide.wrapper --config /etc/aide/aide.conf --check" >> /etc/systemd/system/aidecheck.service
    echo "[Install]" >> /etc/systemd/system/aidecheck.service
    echo "WantedBy=multi-user.target" >> /etc/systemd/system/aidecheck.service
    echo "[Unit]" >> /etc/systemd/system/aidecheck.timer
    echo "Description=Aide check every day at 5AM" >> /etc/systemd/system/aidecheck.timer
    echo "[Timer]" >> /etc/systemd/system/aidecheck.timer
    echo "OnCalendar=*-*-* 05:00:00" >> /etc/systemd/system/aidecheck.timer
    echo "Unit=aidecheck.service" >> /etc/systemd/system/aidecheck.timer
    echo "[Install]" >> /etc/systemd/system/aidecheck.timer
    echo "WantedBy=multi-user.target" >> /etc/systemd/system/aidecheck.timer
    chown root:root /etc/systemd/system/aidecheck.*
    chmod 0644 /etc/systemd/system/aidecheck.* # systemctl daemon-reload
    systemctl enable aidecheck.service
    systemctl --now enable aidecheck.timer
}
1.4(){
    sed -ri 's/chmod\s+[0-7][0-7][0-7]\s+\$\{grub_cfg\}\.new/chmod 400 ${grub_cfg}.new/' /usr/sbin/grub-mkconfig
    sed -ri 's/ && ! grep "\^password" \$\{grub_cfg\}.new >\/dev\/null//' /usr/sbin/grub-mkconfig
    a=`echo -e "Baher13@costco\nBaher13@costco" | grub-mkpasswd-pbkdf2`
    b=`echo $a | awk '{print $11 }'`

    echo "set superusers=root" >> /etc/grub.d/40_BaherCustom
    echo "password_pbkdf2 root $b" >> /etc/grub.d/40_BaherCustom
    chown root:root /boot/grub/grub.cfg
    chmod u-wx,go-rwx /boot/grub/grub.cfg
    echo -e "Baher13@costco\nBaher13@costco" | passwd root
}
1.5(){
    echo "kernel.randomize_va_space = 2" > /etc/sysctl.d/BahersLittleConfiguration.conf
    echo "kernel.randomize_va_space = 2" >> /etc/sysctl.conf
    for file in /etc/sysctl.conf /etc/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /run/sysctl.d/*.conf;
    do if [ -f "$file" ]; then
        grep -Esq "^\s*kernel\.randomize_va_space\s*=\s*([0-1]|[3-9]|[1-9][0- 9]+)" "$file" && sed -ri 's/^\s*kernel\.randomize_va_space\s*=\s*([0-1]|[3- 9]|[1-9][0-9]+)/# &/gi' "$file"
    fi done
    sysctl -w kernel.randomize_va_space=2
    prelink -ua
    apt purge prelink
    echo "* hard core 0" >> /etc/security/limits.conf
    echo "* hard core 0" >> /etc/security/limits.d/ehhh.conf
    echo "fs.suid_dumpable = 0" >> /etc/sysctl.conf
    echo "fs.suid_dumpable = 0" >> /etc/sysctl.d/ehhh.conf
    sysctl -w fs.suid_dumpable=0
    echo "Storage=none" >> /etc/systemd/coredump.conf
    echo "ProcessSizeMax=0" >> /etc/systemd/coredump.conf
    systemctl daemon-reload
}
1.6(){
    apt-get install apparmor
    a=`cat /etc/default/grub | grep GRUB_CMDLINE_LINUX=`
    b=${a::-1}
    c=$b' apparmor=1 security=apparmor"'
    sed -i "/GRUB_CMDLINE_LINUX=/d" /etc/default/grub
    echo $c >> /etc/default/grub
    update-grub
    aa-complain /etc/apparmor.d/*
    aa-enforce /etc/apparmor.d/*
}
1.7(){
    rm /etc/motd
    echo "Authorized uses only. All activity may be monitored and reported." > /etc/issue
    echo "Authorized uses only. All activity may be monitored and reported." > /etc/issue.net
    chown root:root $(readlink -e /etc/motd)
    chmod u-x,go-wx $(readlink -e /etc/motd)
    chown root:root $(readlink -e /etc/issue)
    chmod u-x,go-wx $(readlink -e /etc/issue)
    chown root:root $(readlink -e /etc/issue.net)
    chmod u-x,go-wx $(readlink -e /etc/issue.net)
}
1.8(){
    apt purge gdm3
    echo "[org/gnome/login-screen] \nbanner-message-enable=true \nbanner-message-text='You are totally accessing a government system and I will totally set the fbi on you if unauthorized' \ndisable-user-list=true" >> /etc/gdm3/greeter.dconf-defaults
    dpkg-reconfigure gdm3
    sed '/Enable=true/d' /etc/gdm3/custom.conf
}
1.9(){
    apt upgrade
    apt dist-upgrade
}
CIS1(){
    1.3
    1.4
    1.5
    1.6
    1.7
    1.8
    1.9
}
2.1(){
    apt install ntp
    apt purge chrony
    systemctl --now mask systemd-timesyncd
    echo "restrict -4 default kod nomodify notrap nopeer noquery\nrestrict -6 default kod nomodify notrap nopeer noquery" >> /etc/ntp.conf
    echo "RUNASUSER=ntp" >> /etc/init.d/ntp
    systemctl stop avahi-daaemon.service
    systemctl stop avahi-daemon.socket
    echo "Slapd = ldap, bind9=dns, vsftpd = FTP server, snmpd = Simple Network Management Protocol"
    opts="avahi-daemon cups isc-dhcp-server slapd nfs-kernel-server bind9 vsftpd apache2 dovecot-imapd dovecot-pop3d samba squid snmpd"
    for x in $opts
    do
    read -p "Purge $x [y if not crit service]: " a
    if [ "$a" = "y" ]
    then
    apt purge $x
    fi
    done
    read -p "Purge ALL Mail Services [y if not crit service]: " a
    if [ "$a" = "y" ]
    then
        echo "dc_eximconfig_configtype='local'\ndc_local_interfaces='127.0.0.1 ; ::1'\ndc_readhost=''\ndc_relay_domains=''\ndc_minimaldns='false'\ndc_relay_nets=''\ndc_smarthost=''\ndc_use_split_config='false'\ndc_hide_mailname=''\ndc_mailname_in_oh='true'\ndc_localdelivery='mail_spool'" >> /etc/exim4/update-exim4.conf.conf
        systemctl restart exim4
    fi
    apt purge rsync
    apt purge nis
}
2.2(){
    echo "If anything here is going to be a crit service it is telnet or ldap-utils (to use ldap): "
    opts="nis rsh talk telnet ldap-utils rpcbind"
    for x in $opts
    do
    read -p "Purge $x [y if not crit service]: " a
    if [ "$a" = "y" ]
    then
    apt purge $x
    fi
    done
    opts=`lsof -i -P -n | grep -v "(ESTABLISHED)"`
    opts2=`echo "$opts" | awk '{print $1,$2 }' | sort -u`
    for x in "$opts2"
    do
        service=`echo "$x" | awk '{print $1 }'`
        spid=`echo "$x" | awk '{print $2 }'`
        read -p "Kill $x, pid $spid [y/n]" a
        if [ $a == y ]
        then
            kill -9 $spid
        fi
    done
}
CIS2(){
    2.1
    2.2
}
CIS3(){
    echo "AddressFamily inet" >> /etc/ssh/sshd_config
    systemctl restart sshd
    read -p "Does this system require ipv6 [y/n]" ipv6yn
    if [ $ipv6yn == y ]
    then
        echo "net.ipv6.conf.all.disable_ipv6 = 1 \nnet.ipv6.conf.default.disable_ipv6 = 1" >> /etc/sysctl.conf
        echo "net.ipv6.conf.all.disable_ipv6 = 1 \nnet.ipv6.conf.default.disable_ipv6 = 1" >> /etc/sysctl.d/0.conf
        echo "net.ipv6.conf.all.disable_ipv6 = 1 \nnet.ipv6.conf.default.disable_ipv6 = 1" >> /etc/sysctl.d/zzzz.conf
        sysctl -w net.ipv6.conf.all.disable_ipv6=1
        sysctl -w net.ipv6.conf.default.disable_ipv6=1
        sysctl -w net.ipv6.route.flush=1

    fi
    if command -v nmcli >/dev/null 2>&1 ; then
        nmcli radio all off
    else
    if [ -n "$(find /sys/class/net/*/ -type d -name wireless)" ]; then mname=$(for driverdir in $(find /sys/class/net/*/ -type d -name wireless| xargs -0 dirname); do basename "$(readlink -f "$driverdir"/device/driver/module)";done | sort -u)
        for dm in $mname; do
            echo "install $dm /bin/true" >> /etc/modprobe.d/disable_wireless.conf
            echo "install $dm /bin/true" >> /etc/modprobe.d/00.conf
            echo "install $dm /bin/true" >> /etc/modprobe.d/zzzzz.conf
        done fi
    fi
    echo "net.ipv4.conf.all.send_redirects = 0 \nnet.ipv4.conf.default.send_redirects = 0" >> /etc/sysctl.d/0.conf
    echo "net.ipv4.conf.all.send_redirects = 0 \nnet.ipv4.conf.default.send_redirects = 0" >> /etc/sysctl.d/zzzz.conf
    echo "net.ipv4.conf.all.send_redirects = 0 \nnet.ipv4.conf.default.send_redirects = 0" >> /etc/sysctl.conf
    sysctl -w net.ipv4.conf.all.send_redirects=0
    sysctl -w net.ipv4.conf.default.send_redirects=0
    sysctl -w net.ipv4.route.flush=1
    grep -Els "^\s*net\.ipv6\.conf\.all\.forwarding\s*=\s*1" /etc/sysctl.conf /etc/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /run/sysctl.d/*.conf | while read filename; do sed -ri "s/^\s*(net\.ipv6\.conf\.all\.forwarding\s*)(=)(\s*\S+\b).*$/# *REMOVED* \1/" $filename; done; sysctl -w net.ipv6.conf.all.forwarding=0; sysctl -w net.ipv6.route.flush=1
    echo "net.ipv4.conf.all.accept_source_route = 0 \nnet.ipv4.conf.default.accept_source_route = 0" >> /etc/sysctl.d/0.conf
    echo "net.ipv4.conf.all.accept_source_route = 0 \nnet.ipv4.conf.default.accept_source_route = 0" >> /etc/sysctl.d/zzzz.conf
    echo "net.ipv4.conf.all.accept_source_route = 0 \nnet.ipv4.conf.default.accept_source_route = 0" >> /etc/sysctl.conf
    if [ $ipv6yn == y ]
    then
        grep -Els "^\s*net\.ipv6\.conf\.all\.forwarding\s*=\s*1" /etc/sysctl.conf /etc/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /run/sysctl.d/*.conf | while read filename; do sed -ri "s/^\s*(net\.ipv6\.conf\.all\.forwarding\s*)(=)(\s*\S+\b).*$/# *REMOVED* \1/" $filename; done; sysctl -w net.ipv6.conf.all.forwarding=0; sysctl -w net.ipv6.route.flush=1
        echo "net.ipv6.conf.all.accept_source_route = 0\nnet.ipv6.conf.default.accept_source_route = 0" >> /etc/sysctl.conf
        echo "net.ipv6.conf.all.accept_source_route = 0\nnet.ipv6.conf.default.accept_source_route = 0" >> /etc/0.conf
        echo "net.ipv6.conf.all.accept_source_route = 0\nnet.ipv6.conf.default.accept_source_route = 0" >> /etc/zzzz.conf
        sysctl -w net.ipv6.conf.all.accept_source_route=0
        sysctl -w net.ipv6.conf.default.accept_source_route=0
        sysctl -w net.ipv6.route.flush=1
        echo "net.ipv6.conf.all.accept_redirects = 0\nnet.ipv6.conf.default.accept_redirects = 0\nnet.ipv6.conf.all.accept_ra = 0\nnet.ipv6.conf.default.accept_ra = 0" >> /etc/sysctl.conf
        echo "net.ipv6.conf.all.accept_redirects = 0\nnet.ipv6.conf.default.accept_redirects = 0\nnet.ipv6.conf.all.accept_ra = 0\nnet.ipv6.conf.default.accept_ra = 0" >> /etc/sysctl.d/0.conf
        echo "net.ipv6.conf.all.accept_redirects = 0\nnet.ipv6.conf.default.accept_redirects = 0\nnet.ipv6.conf.all.accept_ra = 0\nnet.ipv6.conf.default.accept_ra = 0" >> /etc/sysctl.d/zzzz.conf
        sysctl -w net.ipv6.conf.all.accept_redirects=0
        sysctl -w net.ipv6.conf.default.accept_redirects=0
        sysctl -w net.ipv6.route.flush=1
        sysctl -w net.ipv6.conf.all.accept_ra=0
        sysctl -w net.ipv6.conf.default.accept_ra=0
        sysctl -w net.ipv6.route.flush=1
    fi
    sysctl -w net.ipv4.conf.all.accept_source_route=0
    sysctl -w net.ipv4.conf.default.accept_source_route=0
    sysctl -w net.ipv4.route.flush=1
    echo "net.ipv4.conf.all.accept_redirects = 0\nnet.ipv4.conf.default.accept_redirects = 0" >> /etc/sysctl.conf
    echo "net.ipv4.conf.all.accept_redirects = 0\nnet.ipv4.conf.default.accept_redirects = 0" >> /etc/sysctl.d/0.conf
    echo "net.ipv4.conf.all.accept_redirects = 0\nnet.ipv4.conf.default.accept_redirects = 0" >> /etc/sysctl.d/zzzz.conf
    sysctl -w net.ipv4.conf.all.accept_redirects=0
    sysctl -w net.ipv4.conf.default.accept_redirects=0
    sysctl -w net.ipv4.route.flush=1
    echo "net.ipv4.conf.all.secure_redirects = 0\nnet.ipv4.conf.default.secure_redirects = 0" >> /etc/sysctl.conf
    echo "net.ipv4.conf.all.secure_redirects = 0\nnet.ipv4.conf.default.secure_redirects = 0" >> /etc/sysctl.d/0.conf
    echo "net.ipv4.conf.all.secure_redirects = 0\nnet.ipv4.conf.default.secure_redirects = 0" >> /etc/sysctl.d/zzzz.conf
    sysctl -w net.ipv4.conf.all.secure_redirects=0
    sysctl -w net.ipv4.conf.default.secure_redirects=0
    sysctl -w net.ipv4.route.flush=1
    echo "net.ipv4.conf.all.log_martians = 1\nnet.ipv4.conf.default.log_martians = 1" >> /etc/sysctl.conf
    echo "net.ipv4.conf.all.log_martians = 1\nnet.ipv4.conf.default.log_martians = 1" >> /etc/sysctl.d/0.conf
    echo "net.ipv4.conf.all.log_martians = 1\nnet.ipv4.conf.default.log_martians = 1" >> /etc/sysctl.d/zzzz.conf
    sysctl -w net.ipv4.conf.all.log_martians=1
    sysctl -w net.ipv4.conf.default.log_martians=1
    sysctl -w net.ipv4.route.flush=1
    echo "net.ipv4.icmp_echo_ignore_broadcasts = 1" >> /etc/sysctl.conf
    echo "net.ipv4.icmp_echo_ignore_broadcasts = 1" >> /etc/sysctl.d/0.conf
    echo "net.ipv4.icmp_echo_ignore_broadcasts = 1" >> /etc/sysctl.d/zzzz.conf
    sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1
    sysctl -w net.ipv4.route.flush=1
    echo "net.ipv4.icmp_ignore_bogus_error_responses = 1\nnet.ipv4.conf.all.rp_filter = 1\nnet.ipv4.conf.default.rp_filter = 1\nnet.ipv4.tcp_syncookies = 1" >> /etc/sysctl.conf
    echo "net.ipv4.icmp_ignore_bogus_error_responses = 1\nnet.ipv4.conf.all.rp_filter = 1\nnet.ipv4.conf.default.rp_filter = 1\nnet.ipv4.tcp_syncookies = 1" >> /etc/sysctl.d/0.conf
    echo "net.ipv4.icmp_ignore_bogus_error_responses = 1\nnet.ipv4.conf.all.rp_filter = 1\nnet.ipv4.conf.default.rp_filter = 1\nnet.ipv4.tcp_syncookies = 1" >> /etc/sysctl.d/zzzz.conf
    sysctl -w net.ipv4.icmp_ignore_bogus_error_responses=1
    sysctl -w net.ipv4.route.flush=1
    sysctl -w net.ipv4.conf.all.rp_filter=1
    sysctl -w net.ipv4.conf.default.rp_filter=1
    sysctl -w net.ipv4.route.flush=1
    sysctl -w net.ipv4.tcp_syncookies=1
    sysctl -w net.ipv4.route.flush=1
    moduleslist="dccp sctp rds tipc"
    for x in $moduleslist
    do
    echo "install $x /bin/true" >> /etc/modprobe.d/$x.conf
    echo "install $x /bin/true" >> /etc/modprobe.d/0.conf
    echo "install $x /bin/true" >> /etc/modprobe.d/zzzz.conf
    done
    apt install ufw
    apt purge iptables-persistent
    ufw allow proto tcp from any to any port 22
    ufw enable
    ufw allow in on lo
    ufw allow out on lo
    ufw deny in from 127.0.0.0/8
    ufw deny in from ::1
    ufw allow out on all
    ufw default deny incoming
    clear
    echo "Open Ports: "
    ss -4tuln
    echo "Firewall: "
    ufw status verbose
    echo "Spawning shell, ensure there is an inbound rule for every open port \n(ufw allow in <port>/<tcp or udp protocol>\n iptables -A INPUT -p <protocol> --dport <port> -m state --state NEW -j ACCEPT/DENY)\nDefault is allow, make sure to use both cmds\nCmd To See: iptables -L INPUT -v -n"
    exec /bin/sh
    ufw allow git
    ufw allow in http
    ufw allow in https
    ufw allow out 53
    ufw logging on
    ufw default deny incoming
    ufw default allow outgoing
    ufw default allow routed
    iptables -A INPUT -i lo -j ACCEPT
    iptables -A OUTPUT -o lo -j ACCEPT
    iptables -A INPUT -s 127.0.0.0/8 -j DROP
    iptables -A OUTPUT -p tcp -m state --state NEW,ESTABLISHED -j ACCEPT
    iptables -A OUTPUT -p udp -m state --state NEW,ESTABLISHED -j ACCEPT
    iptables -A OUTPUT -p icmp -m state --state NEW,ESTABLISHED -j ACCEPT
    iptables -A INPUT -p tcp -m state --state ESTABLISHED -j ACCEPT
    iptables -A INPUT -p udp -m state --state ESTABLISHED -j ACCEPT
    iptables -A INPUT -p icmp -m state --state ESTABLISHED -j ACCEPT
    iptables -P INPUT DROP
    iptables -P OUTPUT ACCEPT
    iptables -P FORWARD DROP
    ##3.5.3.2.4 how?
    if [ $ipv6yn == y ]
    then
        # Flush ip6tables rules
        ip6tables -F
        #Ensure default deny firewall policy
        ip6tables -P INPUT DROP
        ip6tables -P OUTPUT DROP
        ip6tables -P FORWARD DROP
        # Ensure loopback traffic is configured
        ip6tables -A INPUT -i lo -j ACCEPT
        ip6tables -A OUTPUT -o lo -j ACCEPT
        ip6tables -A INPUT -s ::1 -j DROP
        # Ensure outbound and established connections are configured
        ip6tables -A OUTPUT -p tcp -m state --state NEW,ESTABLISHED -j ACCEPT
        ip6tables -A OUTPUT -p udp -m state --state NEW,ESTABLISHED -j ACCEPT
        ip6tables -A OUTPUT -p icmp -m state --state NEW,ESTABLISHED -j ACCEPT
        ip6tables -A INPUT -p tcp -m state --state ESTABLISHED -j ACCEPT
        ip6tables -A INPUT -p udp -m state --state ESTABLISHED -j ACCEPT
        ip6tables -A INPUT -p icmp -m state --state ESTABLISHED -j ACCEPT
        # Open inbound ssh(tcp port 22) connections
        ip6tables -A INPUT -p tcp --dport 22 -m state --state NEW -j ACCEPT
        ip6tables -A INPUT -i lo -j ACCEPT
        ip6tables -A OUTPUT -o lo -j ACCEPT
        ip6tables -A INPUT -s ::1 -j DROP
        ip6tables -A OUTPUT -p tcp -m state --state NEW,ESTABLISHED -j ACCEPT
        ip6tables -A OUTPUT -p udp -m state --state NEW,ESTABLISHED -j ACCEPT
        ip6tables -A OUTPUT -p icmp -m state --state NEW,ESTABLISHED -j ACCEPT
        ip6tables -A INPUT -p tcp -m state --state ESTABLISHED -j ACCEPT
        ip6tables -A INPUT -p udp -m state --state ESTABLISHED -j ACCEPT
        ip6tables -A INPUT -p icmp -m state --state ESTABLISHED -j ACCEPT
        ip6tables -P INPUT DROP
        ip6tables -P OUTPUT ACCEPT
        ip6tables -P FORWARD ACCEPT
        clear
        echo "Spawning shell, ensure there is an inbound rule for every open port \n(ip6tables -A INPUT -p <protocol> --dport <port> -m state --state NEW -j ACCEPT/DROP)\nDefault Accept Them\nCmd To See: ip6tables -L INPUT -v -n"
        exec /bin/sh
    fi
}
CIS4(){ #Finally :)
    apt install auditd audispd-plugins
    systemctl --now enable auditd
    echo "GRUB_CMDLINE_LINUX=\"audit=1\"" >> /etc/default/grub
    echo "GRUB_CMDLINE_LINUX=\"audit_backlog_limit=12496\"" >> /etc/default/grub
    update-grub
    echo "max_log_file = 100\nmax_log_file_action = keep_logs\nspace_left_action = email\nnaction_mail_acct = root\nadmin_space_left_action = halt" >> /etc/audit/auditd.conf
    auditctl -l | grep time-change
    AuditdConf
    #AuditdConf is not used due to potential reboot
}
AuditdConf(){
    systembit=`uname -i`
    MINUIDVAL=`awk '/^\s*UID_MIN/{print $2}' /etc/login.defs`
    if [ "$systembit" = "x86_64"]
    then
        echo "-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change\n-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time- change\n-a always,exit -F arch=b64 -S clock_settime -k time-change\n-a always,exit -F arch=b32 -S clock_settime -k time-change\n-w /etc/localtime -p wa -k time-change" >> /etc/audit/rules.d/0.rules
        echo "-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change\n-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time- change\n-a always,exit -F arch=b64 -S clock_settime -k time-change\n-a always,exit -F arch=b32 -S clock_settime -k time-change\n-w /etc/localtime -p wa -k time-change" >> /etc/audit/rules.d/ZZZZZ.rules
        echo "-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale \n-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale \n-w /etc/issue -p wa -k system-locale\n-w /etc/issue.net -p wa -k system-locale\n-w /etc/hosts -p wa -k system-locale\n-w /etc/network -p wa -k system-locale" >> /etc/audit/rules.d/ZZZZZ.rules
        echo "-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale \n-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale \n-w /etc/issue -p wa -k system-locale\n-w /etc/issue.net -p wa -k system-locale\n-w /etc/hosts -p wa -k system-locale\n-w /etc/network -p wa -k system-locale" >> /etc/audit/rules.d/0.rules
        echo "-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=$MINUIDVAL -F auid!=4294967295 -k perm_mod\n-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=$MINUIDVAL -F auid!=4294967295 -k perm_mod\n-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=$MINUIDVAL -F auid!=4294967295 -k perm_mod\n-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=$MINUIDVAL -F auid!=4294967295 -k perm_mod\n-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=$MINUIDVAL -F auid!=4294967295 -k perm_mod\n-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=$MINUIDVAL -F auid!=4294967295 -k perm_mod" >> /etc/audit/rules.d/0.rules
        echo "-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=$MINUIDVAL -F auid!=4294967295 -k perm_mod\n-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=$MINUIDVAL -F auid!=4294967295 -k perm_mod\n-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=$MINUIDVAL -F auid!=4294967295 -k perm_mod\n-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=$MINUIDVAL -F auid!=4294967295 -k perm_mod\n-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=$MINUIDVAL -F auid!=4294967295 -k perm_mod\n-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=$MINUIDVAL -F auid!=4294967295 -k perm_mod" >> /etc/audit/rules.d/ZZZZZ.rules
        echo "-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=$MINUIDVAL -F auid!=4294967295 -k perm_mod" >> /etc/audit/rules.d/0.rules
        echo "-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=$MINUIDVAL -F auid!=4294967295 -k perm_mod" >> /etc/audit/rules.d/0.rules
        echo "-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=$MINUIDVAL -F auid!=4294967295 -k perm_mod" >> /etc/audit/rules.d/0.rules
        echo "-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=$MINUIDVAL -F auid!=4294967295 -k perm_mod" >> /etc/audit/rules.d/0.rules
        echo "-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=$MINUIDVAL -F auid!=4294967295 -k perm_mod" >> /etc/audit/rules.d/0.rules
        echo "-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=$MINUIDVAL -F auid!=4294967295 -k perm_mod" >> /etc/audit/rules.d/0.rules
        echo "-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=$MINUIDVAL -F auid!=4294967295 -k perm_mod" >> /etc/audit/rules.d/ZZZZZ.rules
        echo "-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=$MINUIDVAL -F auid!=4294967295 -k perm_mod" >> /etc/audit/rules.d/ZZZZZ.rules
        echo "-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=$MINUIDVAL -F auid!=4294967295 -k perm_mod" >> /etc/audit/rules.d/ZZZZZ.rules
        echo "-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=$MINUIDVAL -F auid!=4294967295 -k perm_mod" >> /etc/audit/rules.d/ZZZZZ.rules
        echo "-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=$MINUIDVAL -F auid!=4294967295 -k perm_mod" >> /etc/audit/rules.d/ZZZZZ.rules
        echo "-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=$MINUIDVAL -F auid!=4294967295 -k perm_mod" >> /etc/audit/rules.d/ZZZZZ.rules
        echo "-a always,exit -F arch=b64 -S mount -F auid>=$MINUIDVAL -F auid!=4294967295 -k mounts\n-a always,exit -F arch=b32 -S mount -F auid>=$MINUIDVAL -F auid!=4294967295 -k mounts" >> /etc/audit/rules.d/ZZZZZ.rules
        echo "-a always,exit -F arch=b64 -S mount -F auid>=$MINUIDVAL -F auid!=4294967295 -k mounts\n-a always,exit -F arch=b32 -S mount -F auid>=$MINUIDVAL -F auid!=4294967295 -k mounts" >> /etc/audit/rules.d/0.rules
        echo "-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=$MINUIDVAL -F auid!=4294967295 -k delete\n-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=$MINUIDVAL -F auid!=4294967295 -k delete"  >> /etc/audit/rules.d/0.rules
        echo "-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=$MINUIDVAL -F auid!=4294967295 -k delete\n-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=$MINUIDVAL -F auid!=4294967295 -k delete"  >> /etc/audit/rules.d/ZZZZZ.rules
        echo "-a always,exit -F arch=b64 -C euid!=uid -F euid=0 -Fauid>=1000 -F auid!=4294967295 -S execve -k actions\n-a always,exit -F arch=b32 -C euid!=uid -F euid=0 -Fauid>=$MINUIDVAL -F auid!=4294967295 -S execve -k actions" >> /etc/audit/rules.d/0.rules
        echo "-a always,exit -F arch=b64 -C euid!=uid -F euid=0 -Fauid>=1000 -F auid!=4294967295 -S execve -k actions\n-a always,exit -F arch=b32 -C euid!=uid -F euid=0 -Fauid>=$MINUIDVAL -F auid!=4294967295 -S execve -k actions" >> /etc/audit/rules.d/ZZZZZ.rules
        echo "-w /sbin/insmod -p x -k modules\n-w /sbin/rmmod -p x -k modules\n-w /sbin/modprobe -p x -k modules\n-a always,exit -F arch=b64 -S init_module -S delete_module -k modules" >> /etc/audit/rules.d/0.rules
        echo "-w /sbin/insmod -p x -k modules\n-w /sbin/rmmod -p x -k modules\n-w /sbin/modprobe -p x -k modules\n-a always,exit -F arch=b64 -S init_module -S delete_module -k modules" >> /etc/audit/rules.d/ZZZZZ.rules
    else
        echo "-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time- change\n-a always,exit -F arch=b32 -S clock_settime -k time-change\n-w /etc/localtime -p wa -k time-change" >> /etc/audit/rules.d/0.rules
        echo "-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time- change\n-a always,exit -F arch=b32 -S clock_settime -k time-change\n-w /etc/localtime -p wa -k time-change" >> /etc/audit/rules.d/ZZZZZ.rules
        echo "-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale \n-w /etc/issue -p wa -k system-locale\n-w /etc/issue.net -p wa -k system-locale\n-w /etc/hosts -p wa -k system-locale\n-w /etc/network -p wa -k system-locale" >> /etc/audit/rules.d/0.rules
        echo "-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale \n-w /etc/issue -p wa -k system-locale\n-w /etc/issue.net -p wa -k system-locale\n-w /etc/hosts -p wa -k system-locale\n-w /etc/network -p wa -k system-locale" >> /etc/audit/rules.d/ZZZZZ.rules
        echo "-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=$MINUIDVAL -F auid!=4294967295 -k perm_mod\n-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=$MINUIDVAL -F auid!=4294967295 -k perm_mod\n-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=$MINUIDVAL -F auid!=4294967295 -k perm_mod" >> /etc/audit/rules.d/0.rules
        echo "-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=$MINUIDVAL -F auid!=4294967295 -k perm_mod\n-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=$MINUIDVAL -F auid!=4294967295 -k perm_mod\n-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=$MINUIDVAL -F auid!=4294967295 -k perm_mod" >> /etc/audit/rules.d/ZZZZZ.rules
        echo "-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=$MINUIDVAL -F auid!=4294967295 -k access" >> /etc/audit/rules.d/0.rules
        echo "-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=$MINUIDVAL -F auid!=4294967295 -k access" >> /etc/audit/rules.d/0.rules
        echo "-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=$MINUIDVAL -F auid!=4294967295 -k access" >> /etc/audit/rules.d/0.rules
        echo "-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=$MINUIDVAL -F auid!=4294967295 -k access" >> /etc/audit/rules.d/0.rules
        echo "-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=$MINUIDVAL -F auid!=4294967295 -k access" >> /etc/audit/rules.d/ZZZZZ.rules
        echo "-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=$MINUIDVAL -F auid!=4294967295 -k access" >> /etc/audit/rules.d/ZZZZZ.rules
        echo "-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=$MINUIDVAL -F auid!=4294967295 -k access" >> /etc/audit/rules.d/ZZZZZ.rules
        echo "-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=$MINUIDVAL -F auid!=4294967295 -k access" >> /etc/audit/rules.d/ZZZZZ.rules
        echo "-a always,exit -F arch=b32 -S mount -F auid>=$MINUIDVAL -F auid!=4294967295 -k mounts" >> /etc/audit/rules.d/ZZZZZ.rules
        echo "-a always,exit -F arch=b32 -S mount -F auid>=$MINUIDVAL -F auid!=4294967295 -k mounts" >> /etc/audit/rules.d/0.rules
        echo "-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=$MINUIDVAL -F auid!=4294967295 -k delete" >> /etc/audit/rules.d/ZZZZZ.rules
        echo "-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=$MINUIDVAL -F auid!=4294967295 -k delete" >> /etc/audit/rules.d/0.rules
        echo "-w /sbin/insmod -p x -k modules\n-w /sbin/rmmod -p x -k modules\n-w /sbin/modprobe -p x -k modules\n-a always,exit -F arch=b32 -S init_module -S delete_module -k modules" >> /etc/audit/rules.d/0.rules
        echo "-w /sbin/insmod -p x -k modules\n-w /sbin/rmmod -p x -k modules\n-w /sbin/modprobe -p x -k modules\n-a always,exit -F arch=b32 -S init_module -S delete_module -k modules" >> /etc/audit/rules.d/ZZZZZ.rules
    fi
    echo "-w /etc/group -p wa -k identity\n-w /etc/passwd -p wa -k identity\n-w /etc/gshadow -p wa -k identity\n-w /etc/shadow -p wa -k identity\n-w /etc/security/opasswd -p wa -k identity" >> /etc/audit/rules.d/ZZZZZ.rules
    echo "-w /etc/group -p wa -k identity\n-w /etc/passwd -p wa -k identity\n-w /etc/gshadow -p wa -k identity\n-w /etc/shadow -p wa -k identity\n-w /etc/security/opasswd -p wa -k identity" >> /etc/audit/rules.d/0.rules
    echo "-w /etc/apparmor/ -p wa -k MAC-policy\n-w /etc/apparmor.d/ -p wa -k MAC-policy" >> /etc/audit/rules.d/0.rules
    echo "-w /etc/apparmor/ -p wa -k MAC-policy\n-w /etc/apparmor.d/ -p wa -k MAC-policy" >> /etc/audit/rules.d/ZZZZZ.rules
    echo "-w /var/log/faillog -p wa -k logins\n-w /var/log/lastlog -p wa -k logins\n-w /var/log/tallylog -p wa -k logins" >> /etc/audit/rules.d/0.rules
    echo "-w /var/log/faillog -p wa -k logins\n-w /var/log/lastlog -p wa -k logins\n-w /var/log/tallylog -p wa -k logins" >> /etc/audit/rules.d/ZZZZZ.rules
    echo "-w /var/run/utmp -p wa -k session\n-w /var/log/wtmp -p wa -k logins\n-w /var/log/btmp -p wa -k logins" >> /etc/audit/rules.d/0.rules
    echo "-w /var/run/utmp -p wa -k session\n-w /var/log/wtmp -p wa -k logins\n-w /var/log/btmp -p wa -k logins" >> /etc/audit/rules.d/ZZZZZ.rules
    find / -xdev \( -perm -4000 -o -perm -2000 \) -type f | awk '{print "-a always,exit -F path=" $1 " -F perm=x -F auid>='"$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)"' -F auid!=4294967295 -k privileged" }' >> /etc/audit/rules.d/0.rules
    find / -xdev \( -perm -4000 -o -perm -2000 \) -type f | awk '{print "-a always,exit -F path=" $1 " -F perm=x -F auid>='"$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)"' -F auid!=4294967295 -k privileged" }' >> /etc/audit/rules.d/ZZZZZ.rules
    echo " -w /etc/sudoers -p wa -k scope\n-w /etc/sudoers.d/ -p wa -k scope" >> /etc/audit/rules.d/0.rules
    echo " -w /etc/sudoers -p wa -k scope\n-w /etc/sudoers.d/ -p wa -k scope" >> /etc/audit/rules.d/ZZZZZ.rules
#4.1.17 not included as rebooting :p
}
CIS5(){
    opts="rsyslog cron"
    for x in $opts
    do
        apt install $x
        systemctl --now enable $x
    done
    for x in `ls /etc/rsyslog.d/ | grep '*.conf'`
    do
        echo "\$FileCreateMode 0640" >> /etc/rsyslog.d/$x
        echo "action.resumeRetryCount=\"100\"" >> /etc/rsyslog.d/$x
        echo "queue.type=\"LinkedList\" queue.size=\"1000\")" >> /etc/rsyslog.d/$x
        echo "\$ModLoad imtcp" >> /etc/rsyslog.d/$x
        echo "\$InputTCPServerRun 514" >> /etc/rsyslog.d/$x
    done
    echo "\$FileCreateMode 0640" >> /etc/rsyslog.conf
    echo "action.resumeRetryCount=\"100\"" >> /etc/rsyslog.conf
    echo "queue.type=\"LinkedList\" queue.size=\"1000\")" >> /etc/rsyslog.conf
    echo "\$ModLoad imtcp" >> /etc/rsyslog.conf
    echo "\$InputTCPServerRun 514" >> /etc/rsyslog.conf
    systemctl restart rsyslog
    echo "Compress=yes\nStorage=persistent" >> /etc/systemd/journald.conf
    echo "create 0640 root utmp" >> /etc/logrotate.conf
    chown root:root /etc/crontab
    chmod 0600 /etc/crontab
    chown root:root /etc/cron.hourly/
    chmod 0600 /etc/cron.hourly/
    chown root:root /etc/cron.daily/
    chmod 0600 /etc/cron.daily/
    chown root:root /etc/cron.weekly/
    chmod 0600 /etc/cron.weekly/
    chown root:root /etc/cron.monthly/
    chmod 0600 /etc/cron.monthly/
    chown root:root /etc/cron.d/
    chmod 0600 /etc/cron.d/
    rm /etc/cron.deny
    touch /etc/cron.allow
    chmod 0640 /etc/cron.allow
    chown root:root /etc/cron.allow
    rm /etc/at.deny
    touch /etc/at.allow
    chmod 0640 /etc/at.allow
    chown root:root /etc/at.allow
    apt install sudo
    echo "Defaults use_pty" >> /etc/sudoers
    echo "Defaults logfile=\"/var/log/sudo.log\""  >> /etc/sudoers
    for x in `ls /etc/sudoers.d/`
    do
        echo "Defaults use_pty" >> /etc/sudoers.d/$x
        echo "Defaults logfile=\"/var/log/sudo.log\""  >> /etc/sudoers.d/$x
    done
    chmod -R 0640 /etc/sudoers.d/
    chmod 0640 /etc/sudoers
    chown -R root:root /etc/sudoers.d/
    chown root:root /etc/sudoers
    service sshd reload
    chown root:root /etc/ssh/sshd_config
    chmod og-rwx /etc/ssh/sshd_config
    find /etc/ssh -xdev -type f -name 'ssh_host_*_key' -exec chown root:root {} \;
    find /etc/ssh -xdev -type f -name 'ssh_host_*_key' -exec chmod u-x,go-rwx {} \;
    find /var/log -type f -exec chmod g-wx,o-rwx "{}" + -o -type d -exec chmod g- w,o-rwx "{}" +
    find /etc/ssh -xdev -type f -name 'ssh_host_*_key.pub' -exec chmod u-x,go- wx {} \;
    find /etc/ssh -xdev -type f -name 'ssh_host_*_key.pub' -exec chown root:root {} \;
    userlist=""
    for x in `awk -F: '($3>=1000)&&($1!="nobody"){print $1}' /etc/passwd`
    do
        userlist=$userlist" "$x
    done
    echo "AllowUsers $userlist" >> /etc/ssh/sshd_config
    for x in `ls /ssh/sshd_config.d/ | grep "*conf"`
    do
        echo "AllowUsers $userlist" >> /ssh/sshd_config.d/$x
    done
    setPermissions /ssh/sshd_config.d/ 0640 root root
    setPermissions /etc/ssh 0640 root root
    setPermissions /etc/sudoers.d/ 0640 root root
    setPermissions /etc/cron.hourly/ 0640 root root
    setPermissions /etc/cron.daily/ 0640 root root
    setPermissions /etc/cron.weekly/ 0640 root root
    setPermissions /etc/cron.monthly/ 0640 root root
    toFolder /ssh/sshd_config.d "LogLevel VERBOSE\nX11Forwarding no\nMaxAuthTries 4\nIgnoreRhosts yes\nHostbasedAuthentication no\nPermitRootLogin no\nPermitEmptyPasswords no\nPermitUserEnvironment no\nCiphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128- gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr\n MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2- 512,hmac-sha2-256\nKexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman- group14-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18- sha512,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie- hellman-group-exchange-sha256\nClientAliveInterval 300\nClientAliveCountMax 3\nLoginGraceTime 60\nBanner /etc/issue.net\nUsePAM yes\nAllowTcpForwarding no\nMaxStartups 10:30:60\nMaxSessions 10"
    echo "LogLevel VERBOSE\nX11Forwarding no\nMaxAuthTries 4\nIgnoreRhosts yes\nHostbasedAuthentication no\nPermitRootLogin no\nPermitEmptyPasswords no\nPermitUserEnvironment no\nCiphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128- gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr\n MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2- 512,hmac-sha2-256\nKexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman- group14-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18- sha512,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie- hellman-group-exchange-sha256\nClientAliveInterval 300\nClientAliveCountMax 3\nLoginGraceTime 60\nBanner /etc/issue.net\nUsePAM yes\nAllowTcpForwarding no\nMaxStartups 10:30:60\nMaxSessions 10" >> /etc/ssh/sshd_config
    apt install libpam-pwquality -y
    echo "minlen = 14\nminclass = 4" >> /etc/security/pwquality.conf
    echo "password requisite pam_pwquality.so retry=3\npassword required pam_pwhistory.so remember=5\npassword [success=1 default=ignore] pam_unix.so sha512" >> /etc/pam.d/common-password
    echo "auth required pam_tally2.so onerr=fail audit silent deny=5 unlock_time=900" >> /etc/pam.d/common-auth
    echo "account     requisite    pam_deny.so\naccount     required     pam_tally2.so" >> /etc/pam.d/common-account
    echo "session optional                        pam_umask.so" >> /etc/pam.d/common-session
    echo "PASS_MIN_DAYS 1\nPASS_MAX_DAYS 30\nPASS_WARN_AGE 7\nINACTIVE=30\nUMASK 027\nUSERGROUPS_ENAB no" >> /etc/login.defs
    for x in `awk -F: '($3>=1000)&&($1!="nobody"){print $1}' /etc/passwd`
    do
        chage --mindays 1 $x
        chage --maxdays 30 $x
        chage --warndays 7 $x
        chage --inactive 30 $x
    done
    #do 5.5.1.5
    for x in `awk -F: '($3<1000)&&($1!="root")&&($1!="halt")&&($1!="shutdown")&&($1!="sync"){print $1}' /etc/passwd`
    do
        usermod -s $(which nologin) $x
    done

    for x in `awk -F: '($1!="root"){print $1}' /etc/passwd`
    do
        usermod -L $x
    done
    read -p "Who is the main user: " a
    usermod -U $a
    awk -F: '$1!~/(root|sync|shutdown|halt|^\+)/ && $3<'"$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)"' && $7!~/((\/usr)?\/sbin\/nologin)/ && $7!~/(\/bin)?\/false/ {print $1}' /etc/passwd | while read -r user; do usermod -s "$(which nologin)" "$user"; done
    awk -F: '($1!~/(root|^\+)/ && $3<'"$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)"') {print $1}' /etc/passwd | xargs -I '{}' passwd -S '{}' | awk '($2!~/LK?/) {print $1}' | while read -r user; do usermod -L "$user"; done
    usermod -g 0 root
    grep -RPi '(^|^[^#]*)\s*umask\s+([0-7][0-7][01][0-7]\b|[0-7][0-7][0-7][0- 6]\b|[0-7][01][0-7]\b|[0-7][0-7][0- 6]\b|(u=[rwx]{0,3},)?(g=[rwx]{0,3},)?o=[rwx]+\b|(u=[rwx]{1,3},)?g=[^rx]{1,3}( ,o=[rwx]{0,3})?\b)' /etc/login.defs /etc/profile* /etc/bash.bashrc*
    toFolder /etc/profile "readonly TMOUT=900 ; export TMOUT" "*.sh"
    echo "readonly TMOUT=900 ; export TMOUT" "*.sh" >> /etc/bash.bashrc
    cat /etc/securetty
    clear
    echo "Above is all consoles you can read as root (located in /etc/securetty)\nnano /etc/securetty and remove unneeded/insecure consoles\nSpawning shell"
    exec /bin/sh
    groupadd sugroup
    echo "auth required pam_wheel.so use_uid group=sugroup" >> /etc/pam.d/su
}
CIS6(){
    chown root:root /etc/passwd
    chmod 0644 /etc/passwd
    chown root:root /etc/passwd-
    chmod 0644 /etc/passwd-
    chown root:root /etc/shadow
    chmod 0640 /etc/shadow
    chown root:root /etc/shadow-
    chmod 0640 /etc/shadow-
    chown root:root /etc/gshadow
    chmod 0640 /etc/gshadow
    chown root:root /etc/gshadow-
    chmod 0640 /etc/gshadow-
    clear
    echo "World Writable Files:"
    df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type f -perm -0002
    echo "Spawning Shell, remove write permission if needed"
    exec /bin/sh
    clear
    echo "Unowned files:"
    df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -nouser
    echo "Spawning Shell, set owner to root or user"
    exec /bin/sh
    echo "Ungrouped files:"
    df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -nogroup
    echo "Spawning Shell, set group to root or user"
    exec /bin/sh
    echo "2000+ programs:"
    df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -xdev \( -perm -4000 -o -perm -2000 \) -type f
    echo "Spawning Shell, check for dangerous files"
    exec /bin/sh
    sed -e 's/^\([a-zA-Z0-9_]*\):[^:]*:/\1:x:/' -i /etc/passwd
    awk -F: '($2 == "" ) { print $1 " does not have a password "}' /etc/shadow
    echo "Can be set with passwd -l <username>"
    exec /bin/sh
    for i in $(cut -s -d: -f4 /etc/passwd | sort -u ); do grep -q -P "^.*?:[^:]*:$i:" /etc/group
    if [ $? -ne 0 ]; then
        echo "Group $i is referenced by /etc/passwd but does not exist in /etc/group"
    fi done
    echo "Investigate any above groups"
    exec /bin/sh
    awk -F: '($1!~/(halt|sync|shutdown|nfsnobody)/ && $7!~/^(\/usr)?\/sbin\/nologin(\/)?$/ && $7!~/(\/usr)?\/bin\/false(\/)?$/) { print $1 " " $6 }' /etc/passwd | while read -r user dir; do
    if [ ! -d "$dir" ]; then
        mkdir "$dir"
        chmod 0640 "$dir"
        chown "$user" "$dir"
    fi done
    awk -F: '($1!~/(halt|sync|shutdown)/ && $7!~/^(\/usr)?\/sbin\/nologin(\/)?$/ && $7!~/(\/usr)?\/bin\/false(\/)?$/) { print $1 " " $6 }' | while read -r user dir; do
        if [ ! -d "$dir" ]; then
            echo "User: \"$user\" home directory: \"$dir\" does not exist, creating home directory"
            mkdir "$dir"
            chmod g-w,o-rwx "$dir"
            chown "$user" "$dir"
        else
            owner=$(stat -L -c "%U" "$dir")
            if [ "$owner" != "$user" ]; then
                chmod g-w,o-rwx "$dir"
                chown "$user" "$dir"
            fi
        fi
    done
    awk -F: '($1!~/(halt|sync|shutdown)/ && $7!~/^(\/usr)?\/sbin\/nologin(\/)?$/&& $7!~/(\/usr)?\/bin\/false(\/)?$/) {print $6}' /etc/passwd | while read -r dir; do
        if [ -d "$dir" ]; then
            dirperm=$(stat -L -c "%A" "$dir")
            if [ "$(echo "$dirperm" | cut -c6)" != "-" ] || [ "$(echo "$dirperm" |cut -c8)" != "-" ] || [ "$(echo "$dirperm" | cut -c9)" != "-" ] || [ "$(echo "$dirperm" | cut -c10)" != "-" ]; then
                chmod g-w,o-rwx "$dir"
            fi
        fi
    done
    awk -F: '($1!~/(halt|sync|shutdown)/ && $7!~/^(\/usr)?\/sbin\/nologin(\/)?$/&& $7!~/(\/usr)?\/bin\/false(\/)?$/) { print $1 " " $6 }' | while read -r user dir; do
        if [ -d "$dir" ]; then
            for file in "$dir"/.*; do
                if [ ! -h "$file" ] && [ -f "$file" ]; then
                    fileperm=$(stat -L -c "%A" "$file")
                    if [ "$(echo "$fileperm" | cut -c6)" != "-" ] || [ "$(echo "$fileperm" | cut -c9)" != "-" ]; then
                        chmod go-w "$file"
                    fi
                fi
            done
        fi
    done
    awk -F: '($1!~/(halt|sync|shutdown)/ && $7!~/^(\/usr)?\/sbin\/nologin(\/)?$/ && $7!~/(\/usr)?\/bin\/false(\/)?$/) { print $6 }' /etc/passwd | while read -r dir; do
        if [ -d "$dir" ]; then
            file="$dir/.netrc"
            [ ! -h "$file" ] && [ -f "$file" ] && rm -f "$file"
        fi
    done
    awk -F: '($1!~/(root|halt|sync|shutdown)/ && $7!~/^(\/usr)?\/sbin\/nologin(\/)?$/ && $7!~/(\/usr)?\/bin\/false(\/)?$/) { print $6 }' /etc/passwd | while read -r dir; do
        if [ -d "$dir" ]; then
            file="$dir/.forward"
            [ ! -h "$file" ] && [ -f "$file" ] && rm -r "$file"
        fi
    done
    awk -F: '($1!~/(root|halt|sync|shutdown)/ && $7!~/^(\/usr)?\/sbin\/nologin(\/)?$/ && $7!~/(\/usr)?\/bin\/false(\/)?$/) { print $6 }' /etc/passwd | while read -r dir; do
        if [ -d "$dir" ]; then
            file="$dir/.rhosts"
            [ ! -h "$file" ] && [ -f "$file" ] && rm -r "$file"
        fi
    done
    for x in `cut -d: -f1,3 /etc/passwd | egrep ':[0]{1}$' | cut -d: -f1`
    do
        read -p "Is the $x root, or the equivalent to root?" isroot
        if [ $isroot == n ]
        then
            read -p "New UID: " newuid
            usermod -u $newuid $x
        fi
    done
    clear
    RPCV="$(sudo -Hiu root env | grep '^PATH' | cut -d= -f2)"
    echo "$RPCV" | grep -q "::" && echo "root's path contains a empty directory (::)"
    echo "$RPCV" | grep -q ":$" && echo "root's path contains a trailing (:)"
    for x in $(echo "$RPCV" | tr ":" " "); do
        if [ -d "$x" ]; then
            ls -ldH "$x" | awk '$9 == "." {print "PATH contains current working directory (.)"} $3 != "root" {print $9, "is not owned by root"} substr($1,6,1) != "-" {print $9, "is group writable"} substr($1,9,1) != "-" {print $9, "is world writable"}'
        else
            echo "$x is not a directory"
        fi
    done

    cut -f3 -d":" /etc/passwd | sort -n | uniq -c | while read x ; do [ -z "$x" ] && break
    set - $x
    if [ $1 -gt 1 ]; then
        users=$(awk -F: '($3 == n) { print $1 }' n=$2 /etc/passwd | xargs)
        echo "Duplicate UID ($2): $users"
    fi
    done
    cut -d: -f3 /etc/group | sort | uniq -d | while read x ; do
    echo "Duplicate GID ($x) in /etc/group"
    done
    cut -d: -f1 /etc/passwd | sort | uniq -d | while read -r x; do
    echo "Duplicate login name $x in /etc/passwd"
    done
    cut -d: -f1 /etc/group | sort | uniq -d | while read -r x; do
    echo "Duplicate group name $x in /etc/group"
    done
    sed -ri 's/(^shadow:[^:]*:[^:]*:)([^:]+$)/\1/' /etc/group
    echo "Spawning shell, if any duplicates or root warnings are above, rectify"
    exec /bin/sh
    groupadd hadshadowasprimary
    for x in `awk -F: -v GID="$(awk -F: '($1=="shadow") {print $3}' /etc/group)" '($4==GID) {print $1}' /etc/passwd`
    do
        usermod -g hadshadowasprimary $x
    done

}
toFolder(){
    for x in `find $1 | grep "$3"`
    do
        echo "$2" >> $x
    done
    echo "$2" >> "$1/0.conf"
    echo "$2" >> "$1/ZZZZZ.conf"
}
setPermissions(){
    for x in `find $1 | grep "$5"`
    do
        chmod $2 $x
        chown $3:$4 $x
    done
}
