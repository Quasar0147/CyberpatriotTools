#!/bin/bash
echo "Prequisites: On Debian install ufw. If auto-updates doesnt work check /etc/apt/sources.list"
read -p "What is the opsys Ubuntu, Debian, RedHat or CentOS: " opsys
read -p "What is the Main User (the one you dont change the passwd for)" MainUser
touch /home/$MainUser/Desktop/Script.log
modules(){
    for x in `lsmod | awk '{ print $1 }'`
    do
        if [ $x != "Module" ]
        then
            data="Module: $x    "
            while ((${#data} < 35))
            do
                data="$data "
            done
            location=`modinfo $x | head -n1`
            echo "$data$location"
        fi
    done
    echo "Above is a list of all modules. To remove one, use rmmod <module>. Spawning shell"
    exec /bin/sh
}


daemons() {
    ps -p `ps -C "$(xlsclients | cut -d' ' -f3 | paste - -s -d ',')" --ppid 2 --pid 2 --deselect -o tty,pid | grep ^? | tr "?" " " | xargs | tr " ", ","` -o pid -o user,group=GROUP -o comm,args=ARGS
    echo "above is a list of all daemons, sudo update-rc.d -f <service name> disables, kill \$PID kills"
    echo "spawning shell"
    exec /bin/sh
}



update(){

	case "$opsys" in
	"Debian"|"Ubuntu")
		sudo add-apt-repository -y  ppa:libreoffice/ppa

		sudo apt-get update -y

		sudo apt-get upgrade -y

        sudo apt-get systemd -y

        sudo apt-get systemd-services -y

		sudo apt-get dist-upgrade -y

        apt-get autoremove -y

        apt-get autoclean -y

        apt-get check

		sudo apt-get upgrade firefox -y

		sudo apt-get install clamtk -y

        sudo apt-get install lightdm -y

        sudo apt-get install systemd

        sudo apt-get install iptables

        sudo apt-get install -y clamav clamav-daemon rkhunter auditd aide aide-common unattended-upgrades thunderbird tree apparmor apparmor-utils apparmor-profiles ntp tcpd iptables rsyslog sshguard

        sudo apt-get install --only-upgrade bash

        sudo apt install --only-upgrade sudo

        sudo apt-get install --only-upgrade openssl


	;;
	esac

}

backup() {
	mkdir /BackUps
	sudo cp /etc/sudoers /Backups
	cp /etc/passwd /BackUps
	cp -r /var/log /BackUps
	cp /etc/passwd /BackUps
	cp /etc/group /BackUps
	cp /etc/shadow /BackUps
	cp /var/spool/mail /Backups
    cp /etc /Backups
    cp /home /Backups
    cp /root /Backups
    cp /var /Backups
    cp /srv /Backups
    cp /etc/apt/sources.list /Backups
	for x in `ls /home`
	do
		cp -r /home/$x /BackUps
	done
    mkdir Desktop/Comparatives
    chmod 777 Desktop/Comparatives

    cp /etc/apt/apt.conf.d/10periodic Desktop/Comparatives/
    cp Desktop/logs/allports.log Desktop/Comparatives/
    cp Desktop/logs/allservices.txt Desktop/Comparatives/
    touch Desktop/Comparatives/alltextfiles.txt
    find / -type f -exec grep -Iq . {} \; -and -print >> Desktop/Comparatives/alltextfiles.txt
    cp Desktop/logs/allusers.txt Desktop/Comparatives/
    cp /etc/apache2/apache2.conf Desktop/Comparatives/
    cp /etc/pam.d/common-auth Desktop/Comparatives/
    cp /etc/pam.d/common-password Desktop/Comparatives/
    cp /etc/init/control-alt-delete.conf Desktop/Comparatives/
    crontab -l > Desktop/Comparatives/crontab.log
    cp /etc/group Desktop/Comparatives/
    cp /etc/hosts Desktop/Comparatives/
    touch Desktop/Comparatives/initctl-running.txt
    initctl list | grep running > Desktop/Comparatives/initctl-running.txt
    cp /etc/lightdm/lightdm.conf Desktop/Comparatives/
    cp Desktop/logs/listeningports.log Desktop/Comparatives/
    cp /etc/login.defs Desktop/Comparatives/
    cp Desktop/logs/manuallyinstalled.log Desktop/Comparatives/
    cp /etc/mysql/my.cnf Desktop/Comparatives/
    cp Desktop/logs/packages.log Desktop/Comparatives/
    cp /etc/passwd Desktop/Comparatives/
    cp Desktop/logs/processes.log Desktop/Comparatives/
    cp /etc/rc.local Desktop/Comparatives/
    cp /etc/samba/smb.conf Desktop/Comparatives/
    cp Desktop/logs/socketconnections.log Desktop/Comparatives/
    cp /etc/apt/sources.list Desktop/Comparatives/
    cp /etc/ssh/sshd_config Desktop/Comparatives/
    cp /etc/sudoers Desktop/Comparatives/
    cp /etc/sysctl.conf Desktop/Comparatives/
    tree / -o Desktop/Comparatives/tree.txt -n -p -h -u -g -D -v
    cp /etc/vsftpd.conf Desktop/Comparatives/
    echo "Files on current system have been copied for comparison."
    cp Desktop/Comparatives /BackUps
    chmod 777 -R Desktop/Comparatives/
    chmod 777 -R Desktop/backups
    chmod 777 -R Desktop/logs

}
RKProct(){
    sudo apt-get install clamav clamav-daemon -y
    sudo freshclam
    sudo apt-get install rkhunter
    sudo rkhunter --update
    sudo rkhunter --propupd
    sudo rkhunter --check --rwo
    apt-get install -y chkrootkit clamav rkhunter apparmor apparmor-profiles lynis
    echo "Refer to doc for RKHunter Configuration. This is for expert-level ubuntu bois only."

}
lynisStuff(){
    #TODO
    lynis audit system update
    lynis audit system
    lynis audit system --checkall
    lynis  audit system --cronjob
    lynis  audit system --pentest
    grep -i "^warning" /var/log/lynis-report.dat
    lynis configure settings


}

autoUpdate() {
echo " uss: [$MainUser]# Setting auto updates." >> output.log
	case "$opsys" in
	"Debian"|"Ubuntu")
        sudo apt install unattended-upgrades -y
        sudo dpkg-reconfigure -plow unattended-upgrades
		sed -i -e 's/APT::Periodic::Update-Package-Lists.*\+/APT::Periodic::Update-Package-Lists "1";/' /etc/apt/apt.conf.d/10periodic
		sed -i -e 's/APT::Periodic::Download-Upgradeable-Packages.*\+/APT::Periodic::Download-Upgradeable-Packages "0";/' /etc/apt/apt.conf.d/10periodic
		sed -i 's/x-scheme-handler\/http=.*/x-scheme-handler\/http=firefox.desktop/g' /home/$MainUser/.local/share/applications/mimeapps.list

		echo "###Automatic updates###"
		cat /etc/apt/apt.conf.d/10periodic
		echo ""

	;;
	esac
}

pFiles() {
echo " uss: [$MainUser]# Deleting media files..." >> output.log
	echo "###MEDIA FILES###" >> pFiles.log
    find / -name "*.mov" -type f >> pFiles.log
    find / -name "*.mp4" -type f >> pFiles.log
	find / -name "*.mp3" -type f >> pFiles.log
	#find / -name "*.wav" -type f >> pFiles.log
	echo "###PICTURES###" >> pFiles.log
	find / -name "*.png" -type f >> pFiles.log
    #find / -name "*.jpg" -type f >> pFiles.log
	find / -name "*.jpeg" -type f >> pFiles.log
	find / -name "*.gif" -type f >> pFiles.log
	echo "###BACKDOORS###" >> pFiles.log
	find / -name "*backdoor*.*" -type f >> pFiles.log
	find / -name "*backdoor*.php" -type f >> pFiles.log
    echo "###PHP&PL###"
	find / -name "*.pl" -type f >> pFiles.log
    find / -name "*.php" -type f >> pFiles.log
    echo "All PHP & PL files have been listed above. BE careful with these. ('/var/cache/dictionaries-common/sqspell.php' is a system PHP file)" >> pFiles.log
    echo "###TAR.GZ###"
    find / -name "*.tar.gz" -type f >> pFiles.log
	echo "###FILES WITHOUT GROUPS###" >> pFiles.log
	find / -nogroup >> pFiles.log
	echo "###GAMES###" >> pFiles.log
	dpkg -l | grep -i game
    read -p "Delete media?" a
    if [[ $a = y ]]; then
    	find / -name "*.mp3" -type f -delete
    	find / -name "*.mov" -type f -delete
    	find / -name "*.mp4" -type f -delete
        find / -name "*.gif" -type f -delete
        find / -name "*.png" -type f -delete
    	find / -name "*.jpg" -type f -delete
    	find / -name "*.jpeg" -type f -delete
    echo " uss: [$MainUser]# Media files deleted." >> output.log
    fi
	cat pFiles.log

}

configureFirewall() {
echo " uss: [$MainUser]# Checking for firewall..." >> output.log
	case "$opsys" in
	"Ubuntu"|"Debian")
		dpkg -l | grep ufw >> output.log
		if [ $? -eq 1 ]
		then
			apt-get install ufw >> output.log
		fi
        echo " uss: [$MainUser]# Enabling firewall..." >> output.log
        read -p "Should you use ufw [y/n]" a
        if [ $a = y ]
        then
        ufw enable >>output.log
        ufw logging on high
		ufw status >> output.log
        read -p "Here write down any ports that need allow/deny. Enter to proceed."
		sleep 1
echo " uss: [$MainUser]# Firewall has been turned on and configured." >> output.log
		ufw status
        ufw default allow outgoing
        ufw default deny incoming
        ufw deny cups

        sudo apt-get purge -y cups
        sudo apt-get purge -y bluetooth
        else
    	apt-get install -y iptables
    	apt-get install -y iptables-persistent
    	iptables -t nat -F
    	iptables -t mangle -F
    	iptables -t nat -X
    	iptables -t mangle -X
    	iptables -F
    	iptables -X
    	iptables -P INPUT DROP
    	iptables -P FORWARD DROP
    	iptables -P OUTPUT ACCEPT
    	ip6tables -t nat -F
    	ip6tables -t mangle -F
    	ip6tables -t nat -X
    	ip6tables -t mangle -X
    	ip6tables -F
    	ip6tables -X
    	ip6tables -P INPUT DROP
    	ip6tables -P FORWARD DROP
    	ip6tables -P OUTPUT DROP
        sudo iptables -A INPUT -i lo -j ACCEPT
        sudo iptables -A OUTPUT -o lo -j ACCEPT
        sudo iptables -A INPUT -s 127.0.0.0/8 -j DROP
        sudo iptables -A OUTPUT -p tcp -m state --state NEW,ESTABLISHED -j ACCEPT
        sudo iptables -A OUTPUT -p udp -m state --state NEW,ESTABLISHED -j ACCEPT
        sudo iptables -A OUTPUT -p icmp -m state --state NEW,ESTABLISHED -j ACCEPT
        sudo iptables -A INPUT -p tcp -m state --state ESTABLISHED -j ACCEPT
        sudo iptables -A INPUT -p udp -m state --state ESTABLISHED -j ACCEPT
        sudo iptables -A INPUT -p icmp -m state --state ESTABLISHED -j ACCEPT

    	read -p "Enter primary internet interface: "
    	read interface
    	iptables -A INPUT -s 127.0.0.0/8 -i $interface -j DROP
    	iptables -A INPUT -s 0.0.0.0/8 -j DROP
    	iptables -A INPUT -s 100.64.0.0/10 -j DROP
    	iptables -A INPUT -s 169.254.0.0/16 -j DROP
    	iptables -A INPUT -s 192.0.0.0/24 -j DROP
    	iptables -A INPUT -s 192.0.2.0/24 -j DROP
    	iptables -A INPUT -s 198.18.0.0/15 -j DROP
    	iptables -A INPUT -s 198.51.100.0/24 -j DROP
    	iptables -A INPUT -s 203.0.113.0/24 -j DROP
    	iptables -A INPUT -s 224.0.0.0/3 -j DROP
    	iptables -A OUTPUT -d 127.0.0.0/8 -o $interface -j DROP
    	iptables -A OUTPUT -d 0.0.0.0/8 -j DROP
    	iptables -A OUTPUT -d 100.64.0.0/10 -j DROP
    	iptables -A OUTPUT -d 169.254.0.0/16 -j DROP
    	iptables -A OUTPUT -d 192.0.0.0/24 -j DROP
    	iptables -A OUTPUT -d 192.0.2.0/24 -j DROP
    	iptables -A OUTPUT -d 198.18.0.0/15 -j DROP
    	iptables -A OUTPUT -d 198.51.100.0/24 -j DROP
    	iptables -A OUTPUT -d 203.0.113.0/24 -j DROP
    	iptables -A OUTPUT -d 224.0.0.0/3 -j DROP
    	iptables -A OUTPUT -s 127.0.0.0/8 -o $interface -j DROP
    	iptables -A OUTPUT -s 0.0.0.0/8 -j DROP
    	iptables -A OUTPUT -s 100.64.0.0/10 -j DROP
    	iptables -A OUTPUT -s 169.254.0.0/16 -j DROP
    	iptables -A OUTPUT -s 192.0.0.0/24 -j DROP
    	iptables -A OUTPUT -s 192.0.2.0/24 -j DROP
    	iptables -A OUTPUT -s 198.18.0.0/15 -j DROP
    	iptables -A OUTPUT -s 198.51.100.0/24 -j DROP
    	iptables -A OUTPUT -s 203.0.113.0/24 -j DROP
    	iptables -A OUTPUT -s 224.0.0.0/3 -j DROP
    	iptables -A INPUT -d 127.0.0.0/8 -i $interface -j DROP
    	iptables -A INPUT -d 0.0.0.0/8 -j DROP
    	iptables -A INPUT -d 100.64.0.0/10 -j DROP
    	iptables -A INPUT -d 169.254.0.0/16 -j DROP
    	iptables -A INPUT -d 192.0.0.0/24 -j DROP
    	iptables -A INPUT -d 192.0.2.0/24 -j DROP
    	iptables -A INPUT -d 198.18.0.0/15 -j DROP
    	iptables -A INPUT -d 198.51.100.0/24 -j DROP
    	iptables -A INPUT -d 203.0.113.0/24 -j DROP
    	iptables -A INPUT -d 224.0.0.0/3 -j DROP
    	iptables -A INPUT -i lo -j ACCEPT
    	iptables -A INPUT -p tcp --sport 80 -m conntrack --ctstate ESTABLISHED -j ACCEPT
    	iptables -A INPUT -p tcp --sport 443 -m conntrack --ctstate ESTABLISHED -j ACCEPT
    	iptables -A INPUT -p tcp --sport 53 -m conntrack --ctstate ESTABLISHED -j ACCEPT
    	iptables -A INPUT -p udp --sport 53 -m conntrack --ctstate ESTABLISHED -j ACCEPT
    	iptables -A OUTPUT -p tcp --dport 80 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
    	iptables -A OUTPUT -p tcp --dport 443 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
    	iptables -A OUTPUT -p tcp --dport 53 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
    	iptables -A OUTPUT -p udp --dport 53 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
    	iptables -A OUTPUT -o lo -j ACCEPT
    	iptables -P OUTPUT DROP
    	mkdir /etc/iptables/
    	touch /etc/iptables/rules.v4
    	touch /etc/iptables/rules.v6
    	iptables-save > /etc/iptables/rules.v4
    	ip6tables-save > /etc/iptables/rules.v6
        fi
        read -p "Here write down any ports that need allow/deny. Enter to proceed."
        netstat -punta
        read -p "Next is a list of server ports: "
        netstat -lx
        read -p "Next (Nothing after this): "

	;;
	esac
}
KernelUpgrade(){
    sudo apt-get dist-upgrade

}
AptFix(){
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


}
loginConf() {
	case "$opsys" in
	"Debian")
		typeset -r TMOUT=900
		sed -i 's/greeter-hide-users=.*/greeter-hide-users=true/' /etc/lightdm/lightdm.conf
		sed -i 's/greeter-allow-guest=.*/greeter-allow-guest=false/' /etc/lightdm/lightdm.conf
		sed -i 's/greeter-show-manual-login=.*/greeter-show-manual-login=true/' /etc/lightdm/lightdm.conf
		sed -i 's/allow-guest=.*/allow-guest=false/' /etc/lightdm/lightdm.conf
		sed -i 's/autologin-guest=.*/autologin-guest=false/' /etc/lightdm/lightdm.conf
		sed -i 's/autologin-user=.*/autologin-user=NONE/' /etc/lightdm/lightdm.conf

		sed -i 's/^# disable-user-.*/disable-user-list=true/' /etc/gdm3/greeter.dconf-defaults
		sed -i 's/^# disable-restart-.*/disable-restart-buttons=true/' /etc/gdm3/greeter.dconf-defaults
		sed -i 's/^#  AutomaticLoginEnable.*/AutomaticLoginEnable = false/' /etc/gdm3/custom.conf
        sudo restart lightdm

	;;
	"Ubuntu")
		typeset -r TMOUT=900
        groupdel nopasswdlogin
		if [ -f /etc/lightdm/lightdm.conf ];
		then
			sed -i '$a allow-guest=false' /etc/lightdm/lightdm.conf
			sed -i '$a greeter-hide-users=true' /etc/lightdm/lightdm.conf
			sed -i '$a greeter-show-manual-login=true' /etc/lightdm/lightdm.conf

			cat /etc/ligthdm/lightdm.conf | grep autologin-user >> /dev/null
			if [ $? -eq 0 ]
			then
				USER=`cat /etc/lightdm/lightdm.conf | grep autologin-user | cut -d= -f2`
				if [ "$USER" != "none" ]
				then
					echo "$USER has ben set to autologin."
					sed -i 's/autologin-user=.*/autologin-user=none/' /etc/lightdm/lightdm.conf
				fi
			else
				sed -i '$a autologin-user=none' /etc/lightdm/lightdm.conf
			fi
			cat /etc/lightdm/lightdm.conf

		else
			touch /etc/lightdm/lightdm.conf
			sed -i '$a [SeatDefault]' /etc/lightdm/lightdm.conf
			sed -i '$a allow-guest=false' /etc/lightdm/lightdm.conf
			sed -i '$a greeter-hide-users=true' /etc/lightdm/lightdm.conf
			sed -i '$a greeter-show-manual-login=true' /etc/lightdm/lightdm.conf

			#Finds automatic login user if there is one and takes it out
			cat /etc/ligthdm/lightdm.conf | grep autologin-user >> /dev/null
			if [ $? -eq 0 ]
			then
				USER=`cat /etc/lightdm/lightdm.conf | grep autologin-user | cut -d= -f2`
				if [ "$USER" != "none" ]
				then
					echo "$USER has ben set to autologin."
					sed -i 's/autologin-user=.*/autologin-user=none/' /etc/lightdm/lightdm.conf
				fi
			else
				sed -i '$a autologin-user=none' /etc/lightdm/lightdm.conf
			fi
			cat /etc/lightdm/lightdm.conf

		fi
echo " uss: [$MainUser]# Editing the ../50-ubuntu.conf" >> output.log
		sed -i '$a greeter-hide-users=true' /usr/share/lightdm/lightdm.conf.d/50-ubuntu.conf
		sed -i '$a greeter-show-manual-login=true' /usr/share/lightdm/lightdm.conf.d/50-ubuntu.conf
		sed -i '$a allow-guest=false' /usr/share/lightdm/lightdm.conf.d/50-ubuntu.conf
		#Finds automatic login user if there is one and takes it out
		cat /etc/ligthdm/lightdm.conf | grep autologin-user >> /dev/null
		if [ $? -eq 0 ]
		then
			USER=`cat /etc/lightdm/lightdm.conf | grep autologin-user | cut -d= -f2`
			if [ "$USER" != "none" ]
			then
				echo "$USER has ben set to autologin."
				sed -i 's/autologin-user=.*/autologin-user=none/' /etc/lightdm/lightdm.conf
			fi
		else
			sed -i '$a autologin-user=none' /etc/lightdm/lightdm.conf
		fi
echo " uss: [$MainUser]# Lightdm files have been configured" >> output.log

		cat /usr/share/lightdm/lightdm.conf.d/50-ubuntu.conf

		;;
	esac
}

createUser() {
	read -p "Are there any users you would like to add?[y/n]?" a
	while [ $a = y ]
	do
		read -p "Please enter the name of the user?" user
		adduser $user
		mkdir /home/$user
		read -p "Are there any more users you would like to add?[y/n]: " a
	done


}

chgPasswd(){
    touch password.log
	cut -d: -f1,3 /etc/passwd | egrep ':[0-9]{4}$' | cut -d: -f1 > users
	hUSER=`cut -d: -f1,3 /etc/passwd | egrep ':[0]{1}$' | cut -d: -f1`
	echo "$hUSER is a hidden user"
	sed -i '/root/ d' users
	read -p "What is the password?" PASS
    read -p "Do policies?" Pol
    echo " uss?[$MainUser]# Changing all the user passwords to $PASS." >> output.log
    for x in `awk -F: '($3>=1000)&&($1!="nobody"){print $1}' /etc/passwd`
	do
        if [ $x == $MainUser ]
        then
            echo "$x is you so we dont mess with that : D"
        else
            echo -e "$PASS\n$PASS" | passwd $x >> output.log
		    echo -e "Password for $x has been changed." >> password.log
        fi
        if [ pol = y ];
        then
            chage -M 30 -m 7 -W 15 $x
        fi
	done
echo " uss: [$MainUser]# Passwords have been changed." >> output.log


}
passPol() {
echo " uss: [$MainUser]# Setting password policy..." >> output.log
echo " uss: [$MainUser]# Installing pwquality..." >> output.log
    apt-get install pwquality
    echo 'difok = 3' > /etc/security/pwquality.conf
    echo 'minlen = 8' >> /etc/security/pwquality.conf
    echo 'dcredit = -1' >> /etc/security/pwquality.conf
    echo 'ucredit = -1' >> /etc/security/pwquality.conf
    echo 'lcredit = -1' >> /etc/security/pwquality.conf
    echo 'ocredit = -1' >> /etc/security/pwquality.conf
    echo 'minclass = 3' >> /etc/security/pwquality.conf
    echo 'maxrepeat = 2' >> /etc/security/pwquality.conf
    echo 'gecoscheck = 1' >> /etc/security/pwquality.conf
    echo 'maxsequence = 3' >> /etc/security/pwquality.conf
    for x in `awk -F: '($3>=1000)&&($1!="nobody"){print $1}' /etc/passwd`
    do
        chage -M 30 -m 7 -W 15 $x
    done
echo " uss: [$MainUser]# Password Policy." >> output.log


}

delUser() {
	for x in `awk -F: '($3>=1000)&&($1!="nobody"){print $1}' /etc/passwd`
	do
		read -p "Is $x a valid user?[y/n]: " a
		if [ $a = n ];
		then
			mv /home/$x /home/dis_$x
			sed -i -e "/$x/ s/^#*/#/" /etc/passwd
			sleep 1
		fi
	done

}

admin() {
	for x in `awk -F: '($3>=1000)&&($1!="nobody"){print $1}' /etc/passwd`
	do
		read -p "Is $x considered an admin?[y/n]: " a
		if [ $a = y ]
		then
            gpasswd -a $x lpadmin
            gpasswd -a $x sambashare
			sudo usermod -a -G adm $x
			sudo usermod -a -G sudo $x
		else
			sudo deluser $x adm
			sudo deluser $x sudo
            gpasswd -d $x sudo
            gpasswd -d $x adm
            gpasswd -d $x lpadmin
            gpasswd -d $x sambashare
            gpasswd -d $x root
		fi
	done
    read -p "Check sudoers file for unathorized sudoers now. Hit enter when done"


}

secRoot(){
    read -p "Are you sure you would like to procceed?" a
    if [ $a = y ]
    then
    echo " uss: [$MainUser] # Securing root..." >> output.log
    echo "Due to the nature of the root, and the importance of root access, you will be required to manually enter the root passwd a second time."
	read -p "Root Password: " PASS
	echo -e "$PASS\n$PASS" | passwd root  >> output.log
	sudo passwd -l root
    echo " uss: [$MainUser] # Root has been secured." >> output.log

    fi
}

lockoutPol() {
echo " uss: [$MainUser]# Setting lockout policy..." >> output.log
	sed -i 's/auth\trequisite\t\t\tpam_deny.so\+/auth\trequired\t\t\tpam_deny.so/' /etc/pam.d/common-auth
	sed -i '$a auth\trequired\t\t\tpam_tally2.so deny=5 unlock_time=1800 onerr=fail' /etc/pam.d/common-auth
	sed -i 's/sha512\+/sha512 remember=13/' /etc/pam.d/common-password
    echo " uss: [$MainUser]# Lockout policy set." >> output.log
    cat /etc/pam.d/common-auth


}


sshd() {
echo " uss: [$MainUser]# Checking for ssh..." >> output.log
	dpkg -l | grep openssh-server >> output.log
        	if [ $? -eq 0 ];
        	then
                	read -p "Do you want SSH installed on the system?[y/n]: " a
                	if [ $a = n ];
                	then
                        	apt-get autoremove -y  --purge openssh-server ssh >> output.log
echo " uss: [$MainUser]# SSH has been removed." >> output.log
	         		else
                        echo " uss: [$MainUser]# SSH has been found, securing now..." >> output.log
							sed -i 's/LoginGraceTime .*/LoginGraceTime 60/g' /etc/ssh/sshd_config
                        	sed -i 's/PermitRootLogin .*/PermitRootLogin no/g' /etc/ssh/sshd_config
                        	sed -i 's/Protocol .*/Protocol 2/g' /etc/ssh/sshd_config
                        	sed -i 's/#PermitEmptyPasswords .*/PermitEmptyPasswords no/g' /etc/ssh/sshd_config
                            sed -ir 's/^#?(PasswordAuthentication) .+/\1 yes/' /etc/ssh/sshd_config
                        	sed -i 's/PasswordAuthentication .*/PasswordAuthentication yes/g' /etc/ssh/sshd_config
                        	sed -i 's/X11Forwarding .*/X11Forwarding no/g' /etc/ssh/sshd_config

							sed -i '$a AllowUsers' /etc/ssh/sshd_config
							for x in `awk -F: '($3>=1000)&&($1!="nobody"){print $1}' /etc/passwd`
							do
								sed -i "/^AllowUser/ s/$/ $x /" /etc/ssh/sshd_config
							done
echo " uss: [$MainUser]# SSH has been secured." >> output.log

                	fi
        	else
                	read -p "Does SSH NEED to be installed?[y/n]: " a
                	if [ $a = y ];
                	then
echo " uss: [$MainUser]# Installing and securing SSH now..." >> output.log
                        	apt-get install -y  openssh-server ssh >> output.log

							sed -i 's/LoginGraceTime .*/LoginGraceTime 60/g' /etc/ssh/sshd_config
                        	sed -i 's/PermitRootLogin .*/PermitRootLogin no/g' /etc/ssh/sshd_config
                        	sed -i 's/Protocol .*/Protocol 2/g' /etc/ssh/sshd_config
                        	sed -i 's/#PermitEmptyPasswords .*/PermitEmptyPasswords no/g' /etc/ssh/sshd_config
                        	sed -i 's/PasswordAuthentication .*/PasswordAuthentication yes/g' /etc/ssh/sshd_config
                        	sed -i 's/X11Forwarding .*/X11Forwarding no/g' /etc/ssh/sshd_config

							sed -i '$a AllowUsers' /etc/ssh/sshd_config
							for x in `awk -F: '($3>=1000)&&($1!="nobody"){print $1}' /etc/passwd`
							do
								sed -i "/^AllowUser/ s/$/ $x /" /etc/ssh/sshd_config
							done
			fi
        	fi
            cat /etc/ssh/sshd_config

}

secureShadow() {
echo " uss: [$MainUser]# Securing /etc/shadow..." >> output.log
	chmod 640 /etc/shadow

	ls -l /etc/shadow

}

hakTools() {

echo " uss: [$MainUser]# Removing hacking tools..." >> output.log
	dpkg -l | grep apache >> output.log
	if [ $? -eq 0 ];
	then
        	read -p "Apache has been found. Do you want to remove apache[y/n]: " a
        	if [ $a = y ];
        	then
      	        	apt-get autoremove -y  --purge apache2 >> output.log
			else
            	if [ -e /etc/apache2/apache2.conf ]
				then
					chown -R root:root /etc/apache2
					chown -R root:root /etc/apache
					echo \<Directory \> >> /etc/apache2/apache2.conf
					echo -e ' \t AllowOverride None' >> /etc/apache2/apache2.conf
					echo -e ' \t Order Deny,Allow' >> /etc/apache2/apache2.conf
					echo -e ' \t Deny from all' >> /etc/apache2/apache2.conf
					echo UserDir disabled root >> /etc/apache2/apache2.conf
                    systemctl restart apache2.service
				else
					apt-get install apache2 -y
						chown -R root:root /etc/apache2
						chown -R root:root /etc/apache
						echo \<Directory \> >> /etc/apache2/apache2.conf
						echo -e ' \t AllowOverride None' >> /etc/apache2/apache2.conf
						echo -e ' \t Order Deny,Allow' >> /etc/apache2/apache2.conf
						echo -e ' \t Deny from all' >> /etc/apache2/apache2.conf
						echo UserDir disabled root >> /etc/apache2/apache2.conf

					apt-get install mysql-server -y

					apt-get install php5 -y
					chmod 640 /etc/php5/apache2/php.ini
				fi
        	fi
	else
        echo "Apache is not installed"
		sleep 1
	fi
##Looks for samba
	if [ -d /etc/samba ];
	then
		read -p "Samba has been found on this system, do you want to remove it?[y/n]: " a
		if [ $a = y ];
		then
echo " uss: [$MainUser]# Uninstalling samba..." >> output.log
			sudo apt-get autoremove --purge -y  samba >> output.log
			sudo apt-get autoremove --purge -y  samba >> output.log
            sudo apt-get autoremove samba -y
echo " uss: [$MainUser]# Samba has been removed." >> output.log
		else
			sed -i '82 i\restrict anonymous = 2' /etc/samba/smb.conf
			echo "Config Samba(this script can't)"
		fi
	else
		echo "Samba has not been found."
		sleep 1
	fi
	dpkg -l | grep -i 'vsftpd|ftp' >> output.log
	if [ $? -eq 0 ]
	then
		read -p "FTP Server has been installed, would you like to remove it?[y/n]: " a
		if [ $a = y ]
		then
			PID = `pgrep vsftpd`
			sed -i 's/^/#/' /etc/vsftpd.conf
			kill $PID
			apt-get autoremove -y  --purge vsftpd ftp
		else
			sed -i 's/anonymous_enable=.*/anonymous_enable=NO/' /etc/vsftpd.conf
			sed -i 's/local_enable=.*/local_enable=YES/' /etc/vsftpd.conf
			sed -i 's/#write_enable=.*/write_enable=YES/' /etc/vsftpd.conf
			sed -i 's/#chroot_local_user=.*/chroot_local_user=YES/' /etc/vsftpd.conf
		fi
	else
		echo "FTP has not been found."
		sleep 1
	fi
	dpkg -l | grep tftpd >> output.log
	if [ $? -eq 0 ]
	then
		read -p "TFTPD has been installed, would you like to remove it?[y/n]: " a
		if [ $a = y ]
		then
			apt-get autoremove -y  --purge tftpd
		fi
	else
		echo "TFTPD not found."
		sleep 1
	fi
	dpkg -l | grep -E 'x11vnc|tightvncserver' >> output.log
	if [ $? -eq 0 ]
	then
		read -p "VNC has been installed, would you like to remove it?[y/n]: " a
		if [ $a = y ]
		then
			apt-get autoremove -y  --purge x11vnc tightvncserver
		fi
	else
		echo "VNC not found."
		sleep 1
	fi

	dpkg -l | grep nfs-kernel-server >> output.log
	if [ $? -eq 0 ]
	then
		read -p "NFS has been found, would you like to remove it?[y/n]: " a
		if [ $a = 0 ]
		then
			apt-get autoremove -y  --purge nfs-kernel-server
		fi
	else
		echo "NFS has not been found."
		sleep 1
	fi
	dpkg -l | grep snmp >> output.log
	if [ $? -eq 0 ]
	then
		echo "SNMP HAS BEEN LOCATED!"
		apt-get autoremove -y  --purge snmp
	else
		echo "SNMP has not been found."
		sleep 1
	fi
	dpkg -l | grep -E 'postfix|sendmail' >> output.log
	if [ $? -eq 0 ]
	then
		echo "Mail servers have been found."
        read -p "Remove them(only reason not to is a crit service)?" a
        if [ $a == y ]
        then
        apt-get autoremove -y  --purge postfix sendmail
        else
        apt-get upgrade -y postfix sendmail
        echo "K you do you"
        echo "Configuring"
        echo "Set to the following settings: "
        echo "Internet Site"
        echo "mail.example.com"
        echo "steve"
        echo "mail.example.com, localhost.localdomain, localhost"
        echo "No"
        echo "127.0.0.0/8 [::ffff:127.0.0.0]/104 [::1]/128 192.168.0.0/24"
        echo "0"
        echo "+"
        echo "all"
        read -p "Write down then proceed: "
        sudo dpkg-reconfigure postfix
        echo '#Clients that are excluded from connection count (default: $mynetworks)' > /etc/postfix/main.cf
        echo 'smtpd_client_event_limit_exceptions = $mynetworks' >> /etc/postfix/main.cf
        echo '#The time unit over which client connection rates and other rates are calculated. (default: 60s)' >> /etc/postfix/main.cf
        echo 'anvil_rate_time_unit = 86400s' >> /etc/postfix/main.cf
        echo '#How frequently the server logs peak usage information. (default: 600s)' >> /etc/postfix/main.cf
        echo 'anvil_status_update_time = 120s' >> /etc/postfix/main.cf
        echo '#The maximal number of message delivery requests that any client is allowed to make to this service per time unit. (default: 0) To disable this feature, specify a limit of 0.' >> /etc/postfix/main.cf
        echo 'smtpd_client_message_rate_limit = 200' >> /etc/postfix/main.cf

        echo 'smtpd_sasl_auth_enable = yes' >> /etc/postfix/main.cf
        echo 'smtpd_sasl_local_domain = $myhostname' >> /etc/postfix/main.cf
        echo 'smtpd_tls_security_level=may' >> /etc/postfix/main.cf
        echo 'smtpd_sasl_security_options = noanonymous' >> /etc/postfix/main.cf
        echo 'smtpd_client_restrictions=permit_mynetworks,permit_sasl_authenticated,reject' >> /etc/postfix/main.cf
        read -p "Next you get to hand config a file!: "
        echo '# at the line where commented "#submission inet n" starts, insert the following'
        echo "submission inet n       -       -       -       -       smtpd"
        echo "\t -o syslog_name=postfix/submission"
        echo "\t -o smtpd_tls_security_level=encrypt"
        echo "\t -o smtpd_sasl_auth_enable=yes"
        echo "\t -o smtpd_sasl_security_options=noanonymous"
        echo "\t -o smtpd_reject_unlisted_recipient=no"
        echo "\t -o smtpd_client_restrictions=permit_sasl_authenticated,reject"
        echo "\t -o smtpd_relay_restrictions=permit_sasl_authenticated,reject"
        echo "\t -o smtpd_tls_wrappermode=yes"
        echo "\t -o milter_macro_daemon_name=ORIGINATING"
        read -p "Copy the above lines of code from 'submission inet n' (includes that) down, then press enter when you are ready to enter nano"
        sudo nano /etc/postfix/master.cf
        sudo postconf -e 'smtpd_sasl_type = dovecot'
        sudo postconf -e 'smtpd_sasl_path = private/auth'
        sudo postconf -e 'smtpd_sasl_local_domain ='
        sudo postconf -e 'smtpd_sasl_security_options = noanonymous,noplaintext'
        sudo postconf -e 'smtpd_sasl_tls_security_options = noanonymous'
        sudo postconf -e 'broken_sasl_auth_clients = yes'
        sudo postconf -e 'smtpd_sasl_auth_enable = yes'
        sudo postconf -e 'smtpd_recipient_restrictions = \
        permit_sasl_authenticated,permit_mynetworks,reject_unauth_destination'
        sudo postconf -e 'smtp_tls_security_level = may'
        sudo postconf -e 'smtpd_tls_security_level = may'
        sudo postconf -e 'smtp_tls_note_starttls_offer = yes'
        sudo postconf -e 'smtpd_tls_key_file = /etc/ssl/private/server.key'
        sudo postconf -e 'smtpd_tls_cert_file = /etc/ssl/certs/server.crt'
        sudo postconf -e 'smtpd_tls_loglevel = 1'
        sudo postconf -e 'smtpd_tls_received_header = yes'
        sudo postconf -e "myhostname = mail.example.com"
        sudo postconf -e 'smtpd_tls_loglevel = 4'
        sudo apt install dovecot-core
        echo 'service auth {' > /etc/dovecot/conf.d/10-master.conf
        echo '\t unix_listener auth-userdb {' >> /etc/dovecot/conf.d/10-master.conf
        echo '\t }' >> /etc/dovecot/conf.d/10-master.conf
        echo '\t unix_listener /var/spool/postfix/private/auth {' >> /etc/dovecot/conf.d/10-master.conf
        echo '\t \t mode = 0660' >> /etc/dovecot/conf.d/10-master.conf
        echo '\t \t user = postfix' >> /etc/dovecot/conf.d/10-master.conf
        echo '\t \t group = postfix' >> /etc/dovecot/conf.d/10-master.conf
        echo '\t }' >> /etc/dovecot/conf.d/10-master.conf
        echo '}' >> /etc/dovecot/conf.d/10-master.conf
        read -p "Allow Outlook (Secure n unless specified otherwise): " a
        if [ $a = y ]
        then
        sed -i 's/auth_mechanisms =.*/auth_mechanisms = plain login/' /etc/dovecot/conf.d/10-auth.conf
        else
        sed -i 's/auth_mechanisms =.*/auth_mechanisms = plain/' /etc/dovecot/conf.d/10-auth.conf
        fi
        sudo systemctl restart postfix.service
        read -p "Are you happy now that I HAVE HAD TO CONFIGURE AN ENTIRE MAIL SERVER?: "
        fi
	else
		echo "Mail servers have not been located."
		sleep 1
	fi
	dpkg -l | grep xinetd >> output.log
	if [ $? -eq 0 ]
	then
		echo "XINIT HAS BEEN FOUND!"
		apt-get autoremove -y  --purge xinetd
	else
		echo "XINETD has not been found."
		sleep 1
	fi
    BadThing="nginx pure-ftpd postfix|sendmail nfs-kernel-server xinetd samba tftpd snmp x11vnc|tightvncserver vsftpd|ftp bind9 hydra john apache apache2 cheese mahjongg rhythmbox minetest samba python-samba telnet cups bluetooth *nmap*"
    for i in $BadThing
    do
    read -p "Remove $i?" a
    if [ $a == y ]
    then
    systemctl mask $i
    systemctl disable $i
    systemctl stop $i
    sudo service $i stop
    echo "$i has been disabled"
    else
    echo "Put this in a google doc for config unless you alr configured it (FTP Server, Apache, and Samba(would need to config shares) should be configued.)"
    fi
    done
    GoodThing="ssh proftp"
    for i in $GoodThing
    do
    read -p "Add $i?" a
    if [ $a == y ]
    then
    systemctl unmask $i
    systemctl enable $i
    systemctl start $i
    sudo apt-get install $i
    sudo service $i start
    echo "$i has been enabled"
    echo "If you just did ssh then you need to run config in BASICCIS"
    fi
    done
    sudo fuser -k /var/lib/dpkg/lock-frontend
    sudo apt-get purge -y 0ad 0ad-data 0ad-data-common 2048-qt 3dchess 4digits 7kaa 7kaa-data a7xpg a7xpg-data aajm abe abe-data ace-of-penguins acm adanaxisgpl adanaxisgpl-data adonthell adonthell-data airstrike airstrike-common aisleriot alex4 alex4-data alien-arena alien-arena-data alien-arena-server alienblaster alienblaster-data allure amoebax amoebax-data amphetamine amphetamine-data an anagramarama anagramarama-data angband angband-audio angband-data angrydd animals antigravitaattori ardentryst armagetronad armagetronad-common armagetronad-dedicated asc asc-data asc-music asciijump assaultcube assaultcube-data astromenace astromenace-data-src asylum asylum-data atanks atanks-data atom4 atomix atomix-data attal attal-themes-medieval auralquiz balder2d balder2d-data ballerburg ballz ballz-data ballz-dbg bambam barrage bastet bb bear-factory beneath-a-steel-sky berusky berusky-data berusky2 berusky2-data between billard-gl billard-gl-data biloba biloba-data biniax2 biniax2-data black-box blobandconquer blobandconquer-data blobby blobby-data blobby-server bloboats blobwars blobwars-data blockattack blockout2 blocks-of-the-undead blocks-of-the-undead-data bombardier bomber bomberclone bomberclone-data boswars boswars-data bouncy bovo brainparty brainparty-data briquolo briquolo-data brutalchess bsdgames bsdgames-nonfree btanks btanks-data bubbros bucklespring bucklespring-data bugsquish bumprace bumprace-data burgerspace bve-route-cross-city-south bve-train-br-class-323 bve-train-br-class-323-3dcab bygfoot bygfoot-data bzflag bzflag-client bzflag-data bzflag-server cappuccino caveexpress caveexpress-data cavepacker cavepacker-data cavezofphear ceferino ceferino-data cgoban chessx childsplay childsplay-alphabet-sounds-bg childsplay-alphabet-sounds-ca childsplay-alphabet-sounds-de childsplay-alphabet-sounds-el childsplay-alphabet-sounds-en-gb childsplay-alphabet-sounds-es childsplay-alphabet-sounds-fr childsplay-alphabet-sounds-it childsplay-alphabet-sounds-nb childsplay-alphabet-sounds-nl childsplay-alphabet-sounds-pt childsplay-alphabet-sounds-ro childsplay-alphabet-sounds-ru childsplay-alphabet-sounds-sl childsplay-alphabet-sounds-sv chipw chocolate-common chocolate-doom chromium-bsu chromium-bsu-data circuslinux circuslinux-data colobot colobot-common colobot-common-sounds colobot-common-textures colorcode colossal-cave-adventure connectagram connectagram-data cookietool corsix-th corsix-th-data cowsay cowsay-off crack-attack crafty crafty-bitmaps crafty-books-medium crafty-books-medtosmall crafty-books-small crawl crawl-common crawl-tiles crawl-tiles-data crimson criticalmass criticalmass-data crossfire-client crossfire-client-images crossfire-client-sounds crossfire-common crossfire-maps crossfire-maps crossfire-maps-small crossfire-server crrcsim crrcsim-data csmash csmash-data csmash-demosong cube2 cube2-data cube2-server cultivation curseofwar cutemaze cuyo cuyo-data cyphesis-cpp cyphesis-cpp-clients cyphesis-cpp-mason cytadela cytadela-data d1x-rebirth d2x-rebirth dangen darkplaces darkplaces-server ddnet ddnet-data ddnet-server ddnet-tools dds deal dealer defendguin defendguin-data desmume deutex dhewm3 dhewm3-d3xp dhewm3-doom3 dizzy dodgindiamond2 dolphin-emu dolphin-emu-data doom-wad-shareware doomsday doomsday-common doomsday-data doomsday-server dopewars dopewars-data dossizola dossizola-data drascula drascula-french drascula-german drascula-italian drascula-music drascula-spanish dreamchess dreamchess-data dustracing2d dustracing2d-data dvorak7min dwarf-fortress dwarf-fortress-data eboard eboard-extras-pack1 edgar edgar-data efp einstein el-ixir ember ember-media empire empire-hub empire-lafe endless-sky endless-sky-data endless-sky-high-dpi enemylines3 enemylines7 enigma enigma-data epiphany epiphany-data etoys etqw etqw-server etw etw-data excellent-bifurcation extremetuxracer extremetuxracer-data exult exult-studio ezquake fairymax fb-music-high ffrenzy fgo fgrun fheroes2-pkg filler fillets-ng fillets-ng-data fillets-ng-data-cs fillets-ng-data-nl filters five-or-more fizmo-common fizmo-console fizmo-ncursesw fizmo-sdl2 flare flare-data flare-engine flare-game flight-of-the-amazon-queen flightgear flightgear-data-ai flightgear-data-all flightgear-data-base flightgear-data-models flightgear-phi flobopuyo fltk1.1-games fltk1.3-games foobillardplus foobillardplus-data fortunate.app fortune-anarchism fortune-mod fortune-zh fortunes fortunes-bg fortunes-bofh-excuses fortunes-br fortunes-cs fortunes-de fortunes-debian-hints fortunes-eo fortunes-eo-ascii fortunes-eo-iso3 fortunes-es fortunes-es-off fortunes-fr fortunes-ga fortunes-it fortunes-it-off fortunes-mario fortunes-min fortunes-off fortunes-pl fortunes-ru fortunes-spam fortunes-zh four-in-a-row freealchemist freecell-solver-bin freeciv freeciv-client-extras freeciv-client-gtk freeciv-client-gtk3 freeciv-client-qt freeciv-client-sdl freeciv-data freeciv-server freeciv-sound-standard freecol freedink freedink-data freedink-dfarc freedink-dfarc-dbg freedink-engine freedink-engine-dbg freedm freedoom freedroid freedroid-data freedroidrpg freedroidrpg-data freegish freegish-data freeorion freeorion-data freespace2 freespace2-launcher-wxlauncher freesweep freetennis freetennis-common freevial fretsonfire fretsonfire-game fretsonfire-songs-muldjord fretsonfire-songs-sectoid frogatto frogatto-data frotz frozen-bubble frozen-bubble-data fruit funguloids funguloids-data funnyboat gamazons game-data-packager game-data-packager-runtime gameclock gamine gamine-data garden-of-coloured-lights garden-of-coloured-lights-data gargoyle-free gav gav-themes gbrainy gcompris gearhead gearhead-data gearhead-sdl gearhead2 gearhead2-data gearhead2-sdl geekcode geki2 geki3 gemdropx gemrb gemrb-baldurs-gate gemrb-baldurs-gate-2 gemrb-baldurs-gate-2-data gemrb-baldurs-gate-data gemrb-data gemrb-icewind-dale gemrb-icewind-dale-2 gemrb-icewind-dale-2-data gemrb-icewind-dale-data gemrb-planescape-torment gemrb-planescape-torment-data geneatd gfceu gfpoken gl-117 gl-117-data glaurung glhack glob2 glob2-data glpeces glpeces-data gltron gmchess gmult gnome-2048 gnome-breakout gnome-cards-data gnome-chess gnome-games-app gnome-klotski gnome-mahjongg gnome-mastermind gnome-mines gnome-nibbles gnome-robots gnome-sudoku gnome-tetravex gnubg gnubg-data gnubik gnuboy-sdl gnuboy-x gnuchess gnuchess-book gnudoq gnugo gnujump gnujump-data gnuminishogi gnurobbo gnurobbo-data gnushogi golly gomoku.app gplanarity gpsshogi gpsshogi-data granatier granule gravitation gravitywars greed grhino grhino-data gridlock.app groundhog gsalliere gtans gtkballs gtkboard gtkpool gunroar gunroar-data gweled hachu hannah hannah-data hearse hedgewars hedgewars-data heroes heroes-data heroes-sound-effects heroes-sound-tracks hex-a-hop hex-a-hop-data hexalate hexxagon higan hitori hoichess holdingnuts holdingnuts-server holotz-castle holotz-castle-data holotz-castle-editor hyperrogue hyperrogue-music iagno icebreaker ii-esu infon-server infon-viewer instead instead-data ioquake3 ioquake3-server jag jag-data jester jigzo jigzo-data jmdlx jumpnbump jumpnbump-levels jzip kajongg kanagram kanatest kapman katomic kawari8 kball kball-data kblackbox kblocks kbounce kbreakout kcheckers kdegames-card-data kdegames-card-data-kf5 kdegames-mahjongg-data-kf5 kdiamond ketm ketm-data kfourinline kgoldrunner khangman kigo kiki-the-nano-bot kiki-the-nano-bot-data kildclient killbots kiriki kjumpingcube klickety klines kmahjongg kmines knavalbattle knetwalk knights kobodeluxe kobodeluxe-data kolf kollision komi konquest koules kpat krank kraptor kraptor-data kreversi kshisen ksirk ksnakeduel kspaceduel ksquares ksudoku ktuberling kubrick laby lambdahack late late-data lbreakout2 lbreakout2-data lgc-pg lgeneral lgeneral-data libatlas-cpp-0.6-tools libgemrb libmgba libretro-beetle-pce-fast libretro-beetle-psx libretro-beetle-vb libretro-beetle-wswan libretro-bsnes-mercury-accuracy libretro-bsnes-mercury-balanced libretro-bsnes-mercury-performance libretro-desmume libretro-gambatte libretro-genesisplusgx libretro-mgba libretro-mupen64plus libretro-nestopia libretro-snes9x lierolibre lierolibre-data lightsoff lightyears lincity lincity-ng lincity-ng-data liquidwar liquidwar-data liquidwar-server littlewizard littlewizard-data lmarbles lmemory lolcat londonlaw lordsawar lordsawar-data love lskat ltris lugaru lugaru-data luola luola-data luola-levels luola-nostalgy lure-of-the-temptress macopix-gtk2 madbomber madbomber-data maelstrom magicmaze magicor magicor-data magictouch mah-jong mame mame-data mame-extra manaplus manaplus-data mancala marsshooter marsshooter-data matanza mazeofgalious mazeofgalious-data mednafen mednaffe megaglest megaglest-data meritous meritous-data mgba-common mgba-qt mgba-sdl mgt miceamaze micropolis micropolis-data minetest minetest-data minetest-mod-advspawning minetest-mod-animalmaterials minetest-mod-animals minetest-mod-character-creator minetest-mod-craftguide minetest-mod-homedecor minetest-mod-maidroid minetest-mod-mesecons minetest-mod-mobf minetest-mod-mobf-core minetest-mod-mobf-trap minetest-mod-moreblocks minetest-mod-moreores minetest-mod-nether minetest-mod-pipeworks minetest-mod-player-3d-armor minetest-mod-quartz minetest-mod-torches minetest-mod-unifieddyes minetest-mod-worldedit minetest-server mirrormagic mirrormagic-data mokomaze monopd monsterz monsterz-data moon-buggy moon-lander moon-lander-data moria morris mousetrap mrboom mrrescue mttroff mu-cade mu-cade-data mudlet multitet mupen64plus-audio-all mupen64plus-audio-sdl mupen64plus-data mupen64plus-input-all mupen64plus-input-sdl mupen64plus-qt mupen64plus-rsp-all mupen64plus-rsp-hle mupen64plus-rsp-z64 mupen64plus-ui-console mupen64plus-video-all mupen64plus-video-arachnoid mupen64plus-video-glide64 mupen64plus-video-glide64mk2 mupen64plus-video-rice mupen64plus-video-z64 nestopia nethack-common nethack-console nethack-el nethack-lisp nethack-x11 netmaze netpanzer netpanzer-data netris nettoe neverball neverball-common neverball-data neverputt neverputt-data nexuiz nexuiz-data nexuiz-music nexuiz-server nexuiz-textures nikwi nikwi-data ninix-aya ninvaders njam njam-data noiz2sa noiz2sa-data nsnake nudoku numptyphysics ogamesim ogamesim-www omega-rpg oneisenough oneko onscripter open-adventure open-invaders open-invaders-data openarena openarena-081-maps openarena-081-misc openarena-081-players openarena-081-players-mature openarena-081-textures openarena-085-data openarena-088-data openarena-data openarena-oacmp1 openarena-server openbve-data opencity opencity-data openclonk openclonk-data openlugaru openlugaru-data openmw openmw-cs openmw-data openmw-launcher openpref openssn openssn-data openttd openttd-data openttd-opengfx openttd-openmsx openttd-opensfx opentyrian openyahtzee orbital-eunuchs-sniper orbital-eunuchs-sniper-data osmose-emulator out-of-order overgod overgod-data pachi pachi-data pacman pacman4console palapeli palapeli-data pangzero parsec47 parsec47-data passage pathogen pathological pax-britannica pax-britannica-data pcsx2 pcsxr peg-e peg-solitaire pegsolitaire penguin-command pente pentobi performous performous-tools pescetti petris pgn-extract phalanx phlipple phlipple-data pianobooster picmi pinball pinball-data pinball-dev pingus pingus-data pink-pony pink-pony-data pioneers pioneers-console pioneers-console-data pioneers-data pioneers-metaserver pipenightdreams pipenightdreams-data pipewalker piu-piu pixbros pixfrogger planarity planetblupi planetblupi-common planetblupi-music-midi planetblupi-music-ogg plee-the-bear plee-the-bear-data pokemmo-installer pokerth pokerth-data pokerth-server polygen polygen-data polyglot pong2 powder powermanga powermanga-data pq prboom-plus prboom-plus-game-server primrose projectl purity purity-ng purity-off pybik pybik-bin pybridge pybridge-common pybridge-server pykaraoke pykaraoke-bin pynagram pyracerz pyscrabble pyscrabble-common pyscrabble-server pysiogame pysolfc pysolfc-cardsets pysycache pysycache-buttons-beerabbit pysycache-buttons-crapaud pysycache-buttons-ice pysycache-buttons-wolf pysycache-click-dinosaurs pysycache-click-sea pysycache-dblclick-appleandpear pysycache-dblclick-butterfly pysycache-i18n pysycache-images pysycache-move-animals pysycache-move-food pysycache-move-plants pysycache-move-sky pysycache-move-sports pysycache-puzzle-cartoons pysycache-puzzle-photos pysycache-sounds python-pykaraoke python-renpy qgo qonk qstat qtads quadrapassel quake quake-server quake2 quake2-server quake3 quake3-data quake3-server quake4 quake4-server quakespasm quarry qxw rafkill rafkill-data raincat raincat-data randtype rbdoom3bfg redeclipse redeclipse-common redeclipse-data redeclipse-server reminiscence renpy renpy-demo renpy-thequestion residualvm residualvm-data ri-li ri-li-data ricochet rlvm robocode robotfindskitten rockdodger rocksndiamonds rolldice rott rrootage rrootage-data rtcw rtcw-common rtcw-server runescape salliere sandboxgamemaker sauerbraten sauerbraten-server scid scid-data scid-rating-data scid-spell-data scorched3d scorched3d-data scottfree scummvm scummvm-data scummvm-tools sdl-ball sdl-ball-data seahorse-adventures searchandrescue searchandrescue-common searchandrescue-data sgt-launcher sgt-puzzles shogivar shogivar-data simutrans simutrans-data simutrans-makeobj simutrans-pak128.britain simutrans-pak64 singularity singularity-music sjaakii sjeng sl slashem slashem-common slashem-gtk slashem-sdl slashem-x11 slimevolley slimevolley-data slingshot sludge-engine sm snake4 snowballz solarwolf sopwith spacearyarya spacezero speedpad spellcast sponc spout spring spring-common spring-javaai spring-maps-kernelpanic spring-mods-kernelpanic springlobby starfighter starfighter-data starvoyager starvoyager-data stax steam steam-devices steam-installer steamcmd stockfish stormbaancoureur stormbaancoureur-data sudoku supertransball2 supertransball2-data supertux supertux-data supertuxkart supertuxkart-data swell-foop tagua tagua-data tali tanglet tanglet-data tatan tdfsb tecnoballz tecnoballz-data teeworlds teeworlds-data teeworlds-server tenace tenmado tennix tetrinet-client tetrinet-server tetrinetx tetzle tf tf5 tictactoe-ng tint tintin++ tinymux titanion titanion-data toga2 tomatoes tomatoes-data tome toppler torcs torcs-data torus-trooper torus-trooper-data tourney-manager trackballs trackballs-data transcend treil trigger-rally trigger-rally-data triplane triplea trophy trophy-data trophy-dbg tumiki-fighters tumiki-fighters-data tuxfootball tuxmath tuxmath-data tuxpuck tuxtype tuxtype-data tworld tworld-data typespeed uci2wb ufoai ufoai-common ufoai-data ufoai-maps ufoai-misc ufoai-music ufoai-server ufoai-sound ufoai-textures uhexen2 uhexen2-common uligo unknown-horizons uqm uqm-content uqm-music uqm-russian uqm-voice val-and-rick val-and-rick-data vbaexpress vcmi vectoroids viruskiller visualboyadvance vodovod vor warmux warmux-data warmux-servers warzone2100 warzone2100-data warzone2100-music werewolf wesnoth wesnoth-1.12 wesnoth-1.12-aoi wesnoth-1.12-core wesnoth-1.12-data wesnoth-1.12-did wesnoth-1.12-dm wesnoth-1.12-dw wesnoth-1.12-ei wesnoth-1.12-httt wesnoth-1.12-l wesnoth-1.12-low wesnoth-1.12-music wesnoth-1.12-nr wesnoth-1.12-server wesnoth-1.12-sof wesnoth-1.12-sotbe wesnoth-1.12-thot wesnoth-1.12-tools wesnoth-1.12-trow wesnoth-1.12-tsg wesnoth-1.12-ttb wesnoth-1.12-utbs wesnoth-core wesnoth-music wfut whichwayisup widelands widelands-data wing wing-data wizznic wizznic-data wmpuzzle wolf4sdl wordplay wordwarvi wordwarvi-sound xabacus xabacus xball xbill xblast-tnt xblast-tnt-images xblast-tnt-levels xblast-tnt-models xblast-tnt-musics xblast-tnt-sounds xboard xbomb xbubble xbubble-data xchain xcowsay xdemineur xdesktopwaves xevil xfireworks xfishtank xflip xfrisk xgalaga xgalaga++ xgammon xinv3d xjig xjokes xjump xletters xmabacus xmahjongg xmille xmoto xmoto-data xmountains xmpuzzles xonix xpat2 xpenguins xphoon xpilot-extra xpilot-ng xpilot-ng-client-sdl xpilot-ng-client-x11 xpilot-ng-common xpilot-ng-server xpilot-ng-utils xpuzzles xqf xracer xracer-tools xscavenger xscorch xscreensaver-screensaver-dizzy xshisen xshogi xskat xsok xsol xsoldier xstarfish xsystem35 xteddy xtron xvier xwelltris xye xye-data xzip yahtzeesharp yamagi-quake2 yamagi-quake2-core zangband zangband-data zatacka zaz zaz-data zec zivot zoom-player gameconqueror
    #hamradio
    sudo apt-get purge -y acfax aldo ampr-ripd antennavis aprsdigi aprx ax25-apps ax25-tools ax25-xtools ax25mail-utils axmail baycomepp baycomusb chirp comptext comptty cqrlog cubicsdr cutesdr cw cwcp cwdaemon d-rats dablin direwolf ebook2cw ebook2cwgui fbb fccexam flamp fldigi flmsg flrig flwrap freedv glfer gnss-sdr gnuais gnuaisgui gpredict gqrx-sdr grig gsmc hamexam hamfax icom inspectrum klog libecholib1.3 libfap6 libhamlib-utils limesuite linpac linpsk lysdr morse morse-x morse2ascii multimon nec2c owx p10cfgd predict predict-gsat psk31lx pydxcluster pyqso qrq qsstv qtel qtel-icons quisk remotetrx soapyosmo-common0.6 soapyremote-server soapysdr-module-airspy soapysdr-module-all soapysdr-module-audio soapysdr-module-bladerf soapysdr-module-hackrf soapysdr-module-lms7 soapysdr-module-mirisdr soapysdr-module-osmosdr soapysdr-module-redpitaya soapysdr-module-remote soapysdr-module-rfspace soapysdr-module-rtlsdr soapysdr-module-uhd soapysdr-tools soapysdr0.6-module-airspy soapysdr0.6-module-all soapysdr0.6-module-audio soapysdr0.6-module-bladerf soapysdr0.6-module-hackrf soapysdr0.6-module-lms7 soapysdr0.6-module-mirisdr soapysdr0.6-module-osmosdr soapysdr0.6-module-redpitaya soapysdr0.6-module-remote soapysdr0.6-module-rfspace soapysdr0.6-module-rtlsdr soapysdr0.6-module-uhd soundmodem splat svxlink-calibration-tools svxlink-gpio svxlink-server svxreflector tk2 tk5 tlf trustedqsl tucnak twclock twpsk uhd-soapysdr uronode wsjtx wwl xastir xcwcp xdemorse xdx xlog xlog-data xnec2c xnecview yagiuda z8530-utils2
    sudo apt-get purge -y akqml bino browser-plugin-gnash browser-plugin-vlc cclive crtmpserver crtmpserver-apps crtmpserver-dev crtmpserver-libs deepin-movie dtv-scan-tables dumphd dvblast dvbstreamer dvdrip-utils ffmpeg flowblade flvmeta freetuxtv frei0r-plugins get-flash-videos gmlive gnash-common-opengl gnash-ext-fileio gnash-ext-lirc gnash-ext-mysql gnash-opengl gnome-dvb-client gnome-dvb-daemon gnome-mpv gnome-twitch gnome-twitch-player-backend-gstreamer-cairo gnome-twitch-player-backend-gstreamer-clutter gnome-twitch-player-backend-gstreamer-opengl gnome-twitch-player-backend-mpv-opengl grilo-plugins-dvb-daemon growisofs gst123 gstreamer1.0-crystalhd h264enc hdmi2usb-fx2-firmware i965-va-driver i965-va-driver-shaders imagination imagination-common kazam klash-opengl kodi kodi-bin kodi-data kodi-eventclients-common kodi-eventclients-kodi-send kodi-eventclients-ps3 kodi-eventclients-wiiremote kodi-pvr-hts kodi-repository-kodi kylin-video libaacs0 libde265-examples libdvbcsa1 libffmpegthumbnailer4v5 libheif-examples libqtav1 libqtavwidgets1 libtotem0 libvlc-bin libxine2-xvdr lives-plugins livestreamer m2vrequantiser mediathekview mencoder minitube mjpegtools-gtk mplayer mplayer-gui mpv multicat nageru nomnom nordlicht obs-plugins obs-studio oggvideotools ogmrip-dirac ogmrip-oggz ogmrip-plugins openalpr openalpr-daemon openshot openshot-qt photofilmstrip qml-module-qtav qstopmotion qtav-players ser-player shotdetect simplescreenrecorder smplayer-l10n smtube sreview-common sreview-detect sreview-encoder sreview-master sreview-web streamlink subliminal-nautilus swfdec-gnome swfdec-mozilla tablet-encode transcode transmageddon tsdecrypt tvnamer va-driver-all vdpau-driver-all vdr-plugin-dvbhddevice vdr-plugin-dvbsddevice vdr-plugin-epgsync vdr-plugin-osdteletext vdr-plugin-satip vdr-plugin-skinenigmang vdr-plugin-softhddevice vdr-plugin-svdrpext vdr-plugin-svdrpext vdr-plugin-svdrposd vdr-plugin-vnsiserver vlc-bin vlc-plugin-access-extra vlc-plugin-base vlc-plugin-fluidsynth vlc-plugin-notify vlc-plugin-qt vlc-plugin-samba vlc-plugin-skins2 vlc-plugin-svg vlc-plugin-video-output vlc-plugin-video-splitter vlc-plugin-visualization vlc-plugin-vlsub vlc-plugin-zvbi voctomix voctomix-core voctomix-gui voctomix-outcasts vokoscreen webcamoid webcamoid-data webcamoid-plugins winff-data winff-gtk2 winff-qt x265 xbmc-pvr-argustv xbmc-pvr-dvbviewer xbmc-pvr-iptvsimple xbmc-pvr-mediaportal-tvserver xbmc-pvr-mythtv-cmyth xbmc-pvr-nextpvr xbmc-pvr-njoy xbmc-pvr-tvheadend-hts xbmc-pvr-vdr-vnsi xbmc-pvr-vuplus xbmc-pvr-wmc xvidenc totem*
    sudo apt-get purge -y wireshark* *nmap* *medusa* john* *sqlmap* hydra* zenmap ophcrack* tcpdump* kismet* snort* fwsnort *nessus* netcat* aircrack-ng nikto wifite yersinia hashcat* *macchanger* pixiewps bbqsql proxychains* whatweb dirb traceroute *httrack* *openvas* 4g8 acccheck airgraph-ng bittorrent* bittornado* bluemon btscanner buildtorrent brutespray dsniff ettercap* hunt nast netsniff-ng python-scapy sipgrep sniffit tcpick tcpreplay tcpslice tcptrace tcptraceroute tcpxtract irpas mdk3 reaver slowhttptest ssldump sslstrip thc-ipv6 bro* darkstat dnstop flowscan nfstrace* nstreams ntopng* ostinato softflowd tshark

    cd /usr/local/src
    sudo wget http:/www.rfxn.com/downloads/maldetect-current.tar.gz
    sudo tar -xzf maldetect-current.tar.gz
    cd maldetect-*
    systemctl daemon-reload
    clear
    echo "Check ports"
    ufw status
    read -p "Write down all ports you want to shut down or enable, enter to procceed."
    clear
    apt list --installed
    read -p "These are all the packages installed, write down all the packages to remove, then hit enter to proceed"
    clear
    echo "Netcat and all other instances have been removed."

    apt-get purge john -y  -qq
    apt-get purge john-data -y  -qq
    clear
    echo "John the Ripper has been removed."

    apt-get purge hydra -y  -qq
    apt-get purge hydra-gtk -y  -qq
    clear
    echo "Hydra has been removed."

    apt-get purge aircrack-ng -y  -qq
    clear
    echo "Aircrack-NG has been removed."

    apt-get purge fcrackzip -y  -qq
    clear
    echo "FCrackZIP has been removed."

    apt-get purge lcrack -y  -qq
    clear
    echo "LCrack has been removed."

    apt-get purge ophcrack -y  -qq
    apt-get purge ophcrack-cli -y  -qq
    clear
    echo "OphCrack has been removed."

    apt-get purge pdfcrack -y  -qq
    clear
    echo "PDFCrack has been removed."

    apt-get purge pyrit -y  -qq
    clear
    echo "Pyrit has been removed."

    apt-get purge rarcrack -y  -qq
    clear
    echo "RARCrack has been removed."

    apt-get purge sipcrack -y  -qq
    clear
    echo "SipCrack has been removed."

    apt-get purge irpas -y  -qq
    clear
    echo "IRPAS has been removed."

    clear
    echo 'Are there any hacking tools shown? (not counting libcrack2:amd64 or cracklib-runtime)'
    dpkg -l | egrep "crack|hack" >> Script.log

    apt-get purge logkeys -y  -qq
    clear
    echo "LogKeys has been removed."

    apt-get purge zeitgeist-core -y  -qq
    apt-get purge zeitgeist-datahub -y  -qq
    apt-get purge python-zeitgeist -y  -qq
    apt-get purge rhythmbox-plugin-zeitgeist -y  -qq
    apt-get purge zeitgeist -y  -qq
    echo "Zeitgeist has been removed."

    apt-get purge nfs-kernel-server -y  -qq
    apt-get purge nfs-common -y  -qq
    apt-get purge portmap -y  -qq
    apt-get purge rpcbind -y  -qq
    apt-get purge autofs -y  -qq
    echo "NFS has been removed."


    apt-get purge inetd -y  -qq
    apt-get purge openbsd-inetd -y  -qq
    apt-get purge xinetd -y  -qq
    apt-get purge inetutils-ftp -y  -qq
    apt-get purge inetutils-ftpd -y  -qq
    apt-get purge inetutils-inetd -y  -qq
    apt-get purge inetutils-ping -y  -qq
    apt-get purge inetutils-syslogd -y  -qq
    apt-get purge inetutils-talk -y  -qq
    apt-get purge inetutils-talkd -y  -qq
    apt-get purge inetutils-telnet -y  -qq
    apt-get purge inetutils-telnetd -y  -qq
    apt-get purge inetutils-tools -y  -qq
    apt-get purge inetutils-traceroute -y  -qq
    echo "Inetd (super-server) and all inet utilities have been removed."

    clear
    apt-get purge vnc4server -y  -qq
    apt-get purge vncsnapshot -y  -qq
    apt-get purge vtgrab -y  -qq
    echo "VNC has been removed."

    clear
    apt-get purge snmp -y  -qq
    echo "SNMP has been removed."

    clear
    cp /etc/login.defs /home/$MainUser/backups/
    sed -i '160s/.*/PASS_MAX_DAYS\o01130/' /etc/login.defs
    sed -i '161s/.*/PASS_MIN_DAYS\o0113/' /etc/login.defs
    sed -i '162s/.*/PASS_MIN_LEN\o0118/' /etc/login.defs
    sed -i '163s/.*/PASS_WARN_AGE\o0117/' /etc/login.defs
    echo "Password policies have been set with /etc/login.defs."

    clear
    cp /etc/security/pwquality.conf /home/$MainUser/backups/
    cp /etc/security/pwquality.conf /home/$MainUser/backups/


    clear
    apt-get install iptables -y  -qq
    iptables -A INPUT -p all -s localhost  -i eth0 -j DROP
    echo "All outside packets from internet claiming to be from loopback are denied."

    clear
    cp /etc/init/control-alt-delete.conf /home/$MainUser/backups/
    sed '/^exec/ c\exec false' /etc/init/control-alt-delete.conf
    echo "Reboot using Ctrl-Alt-Delete has been disabled."

    clear
    apt-get install apparmor apparmor-profiles -y  -qq
    echo "AppArmor has been installed."

    clear
    crontab -l > /home/$MainUser/backups/crontab-old
    crontab -r
    echo "Crontab has been backed up. All startup tasks have been removed from crontab."

    clear
    cd /etc/
    /bin/rm -f cron.deny at.deny
    echo root >cron.allow
    echo root >at.allow
    /bin/chown root:root cron.allow at.allow
    /bin/chmod 400 cron.allow at.allow
    cd ..
    echo "Only root allowed in cron."

    clear
    chmod 777 /etc/apt/apt.conf.d/10periodic
    cp /etc/apt/apt.conf.d/10periodic /home/$MainUser/backups/
    echo -e "APT::Periodic::Update-Package-Lists \"1\";\nAPT::Periodic::Download-Upgradeable-Packages \"1\";\nAPT::Periodic::AutocleanInterval \"1\";\nAPT::Periodic::Unattended-Upgrade \"1\";" > /etc/apt/apt.conf.d/10periodic
    chmod 644 /etc/apt/apt.conf.d/10periodic
    echo "Daily update checks, download upgradeable packages, autoclean interval, and unattended upgrade enabled."

    clear
    chmod 777 /etc/apt/sources.list
    cp /etc/apt/sources.list /home/$MainUser/backups/
    chmod 644 /etc/apt/sources.list
    echo "Apt Repositories have been backed up."

    clear

    clear
    echo "Check to verify that all update settings are correct."
    update-manager

    clear
    apt-get update
    apt-get upgrade openssl libssl-dev
    apt-cache policy openssl libssl-dev
    echo "OpenSSL heart bleed bug has been fixed."

    clear
    if [[ $(grep root /etc/passwd | wc -l) -gt 1 ]]
    then
    grep root /etc/passwd | wc -l
    echo -e "UID 0 is not correctly set to root. Please fix.\nPress enter to continue..."
    read ing
    else
    echo "UID 0 is correctly set to root."
    fi

    clear
    mkdir -p ~/Desktop/logs
    chmod 777 ~/Desktop/logs
    echo "Logs folder has been created on the Desktop."

    clear
    touch ~/Desktop/logs/allusers.txt
    uidMin=$(grep "^UID_MIN" /etc/login.defs)
    uidMax=$(grep "^UID_MAX" /etc/login.defs)
    echo -e "User Accounts:" >> ~/Desktop/logs/allusers.txt
    awk -F':' -v "min=${uidMin##UID_MIN}" -v "max=${uidMax##UID_MAX}" '{ if ( $3 >= min && $3 <= max  && $7 != "/sbin/nologin" ) print $0 }' /etc/passwd >> ~/Desktop/logs/allusers.txt
    echo -e "\nSystem Accounts:" >> ~/Desktop/logs/allusers.txt
    awk -F':' -v "min=${uidMin##UID_MIN}" -v "max=${uidMax##UID_MAX}" '{ if ( !($3 >= min && $3 <= max  && $7 != "/sbin/nologin")) print $0 }' /etc/passwd >> ~/Desktop/logs/allusers.txt
    echo "All users have been logged."
    cp /etc/services ~/Desktop/logs/allports.log
    echo "All ports log has been created."
    dpkg -l > ~/Desktop/logs/packages.log
    echo "All packages log has been created."
    apt-mark showmanual > ~/Desktop/logs/manuallyinstalled.log
    echo "All manually instealled packages log has been created."
    service --status-all > ~/Desktop/logs/allservices.txt
    echo "All running services log has been created."
    ps ax > ~/Desktop/logs/processes.log
    echo "All running processes log has been created."
    ss -l > ~/Desktop/logs/socketconnections.log
    echo "All socket connections log has been created."
    sudo netstat -tulpn > ~/Desktop/logs/listeningports.log
    echo "All listening ports log has been created."
    cp /var/log/auth.log ~/Desktop/logs/auth.log
    echo "Auth log has been created."
    cp /var/log/syslog ~/Desktop/logs/syslog.log
    echo "System log has been created."

    clear
    apt-get install tree -y  -qq
    apt-get install diffuse -y  -qq
    echo "Tree and diffuse installed"
    echo "Expect this to freeze, it is running a find cmd"
    find / -iname "backdoor"
    clear

}
BASICCIS3(){
    startTime=$(date +"%s")
    printTime()
    {
    endTime=$(date +"%s")
    diffTime=$(($endTime-$startTime))
    if [ $(($diffTime / 60)) -lt 10 ]
    then
    	if [ $(($diffTime % 60)) -lt 10 ]
    	then
    		echo -e "0$(($diffTime / 60)):0$(($diffTime % 60)) -- $1" >> Script.log
    	else
    		echo -e "0$(($diffTime / 60)):$(($diffTime % 60)) -- $1" >> Script.log
    	fi
    else
    	if [ $(($diffTime % 60)) -lt 10 ]
    	then
    		echo -e "$(($diffTime / 60)):0$(($diffTime % 60)) -- $1" >> Script.log
    	else
    		echo -e "$(($diffTime / 60)):$(($diffTime % 60)) -- $1" >> Script.log
    	fi
    fi
    }

    touch Script.log
    echo > Script.log
    chmod 777 Script.log

    if [[ $EUID -ne 0 ]]
    then
    echo This script must be run as root
    exit
    fi
    echo "Script is being run as root."

    echo "The current OS is Linux Ubuntu."

    mkdir -p ~/Desktop/backups
    chmod 777 ~/Desktop/backups
    echo "Backups folder created on the Desktop."

    cp /etc/group /home/$MainUser/backups/
    cp /etc/passwd /home/$MainUser/backups/

    echo "/etc/group and /etc/passwd files backed up."
    for x in `awk -F: '($3>=1000)&&($1!="nobody"){print $1}' /etc/passwd`
	do
    clear
    echo $x
    echo Delete $x? y or n
    read yn1
    if [ $yn1 == y ]
    then
    	userdel -r $x
    	echo "$x has been deleted."
    fi
    done
    clear

    echo Type user account names of users you want to add, with a space in between
    read -a usersNew

    usersNewLength=${#usersNew[@]}

    for (( i=0;i<$usersNewLength;i++))
    do
    clear
    echo ${usersNew[${i}]}
    adduser ${usersNew[${i}]}
    echo "A user account for ${usersNew[${i}]} has been created."
    clear
    echo Make ${usersNew[${i}]} administrator? y or n
    read ynNew
    echo Policies y or n
    read Policies
    if [ $ynNew == y ]
    then
    	gpasswd -a ${usersNew[${i}]} sudo
    	gpasswd -a ${usersNew[${i}]} adm
    	gpasswd -a ${usersNew[${i}]} lpadmin
    	gpasswd -a ${usersNew[${i}]} sambashare
    	echo "${usersNew[${i}]} has been made an administrator."
    else
    	echo "${usersNew[${i}]} has been made a standard user."
    fi
    if [ $Policies == y ]
    then
    passwd -x30 -n3 -w7 ${usersNew[${i}]}
    usermod -L ${usersNew[${i}]}
    echo "${usersNew[${i}]}'s password has been given a maximum age of 30 days, minimum of 3 days, and warning of 7 days. ${users[${i}]}'s account has been locked."
    fi
    done
    echo "Get Nakul for this portion."
    echo Does this machine need Samba?
    read sambaYN
    echo Does this machine need FTP?
    read ftpYN
    echo Does this machine need SSH?
    read sshYN
    echo Does this machine need Telnet?
    read telnetYN
    echo Does this machine need Mail?
    read mailYN
    echo Does this machine need Printing?
    read printYN
    echo Does this machine need MySQL?
    read dbYN
    echo Will this machine be a Web Server?
    read httpYN
    echo Does this machine need DNS?
    read dnsYN
    echo Does this machine allow media files?
    read mediaFilesYN
    echo Does this machine need IPv6?
    read ipv6YN
    read -p "Continuing will finalize above changes, are you sure you want to proceed (If not then close terminal): "
    if [ $ipv6YN == n ]
    then
    echo -e "\n\n# Disable IPv6\nnet.ipv6.conf.all.disable_ipv6 = 1\nnet.ipv6.conf.default.disable_ipv6 = 1\nnet.ipv6.conf.lo.disable_ipv6 = 1" >> /etc/sysctl.conf
    sysctl -p >> /dev/null
    echo "IPv6 has been disabled."
    fi

    clear
    if [ $sambaYN == n ]
    then
    ufw deny netbios-ns
    ufw deny netbios-dgm
    ufw deny netbios-ssn
    ufw deny microsoft-ds
    apt-get purge samba -y  -qq
    apt-get purge samba-common -y   -qq
    apt-get purge samba-common-bin -y  -qq
    apt-get purge samba4 -y  -qq
    systemctl disable smbd
    systemctl disable nmbd
    ufw deny 137:138/udp
    ufw deny 139,445/tcp
    clear
    echo "netbios-ns, netbios-dgm, netbios-ssn, and microsoft-ds ports have been denied. Samba has been removed."
    elif [ $sambaYN == y ]
    then
    ufw allow netbios-ns
    ufw allow netbios-dgm
    ufw allow netbios-ssn
    ufw allow microsoft-ds
    apt-get install samba -y  -qq
    apt-get install system-config-samba -y  -qq
    cp /etc/samba/smb.conf /home/$MainUser/backups/
    if [ "$(grep '####### Authentication #######' /etc/samba/smb.conf)"==0 ]
    then
    	sed -i 's/####### Authentication #######/####### Authentication #######\nsecurity = user/g' /etc/samba/smb.conf
    fi
    sed -i 's/usershare allow guests = no/usershare allow guests = yes/g' /etc/samba/smb.conf
    read -p "Check for samba admins to see who has admin."
    read -p "Samba passwd?" SPASS
    for x in `awk -F: '($3>=1000)&&($1!="nobody"){print $1}' /etc/passwd`
    do
    	echo -e "$SPASS\n$SPASS" | smbpasswd -a $x
    	echo "$x has been given the password '$SPASS' for Samba."
    done
    echo "netbios-ns, netbios-dgm, netbios-ssn, and microsoft-ds ports have been allowed. Samba config file has been configured."
    systemctl enable smbd
    systemctl enable nmbd
    systemctl status smbd
    systemctl status nmbd
    ufw allow 137:138/udp
    ufw allow 139,445/tcp
    cp /etc/samba/smb.conf{,.backup}
    read -p "Configure samba, high level linux bois only"
    clear
    else
    echo Response not recognized.
    fi
    echo "Samba is complete."

    clear
    if [ $ftpYN == n ]
    then
    ufw deny ftp
    ufw deny sftp
    ufw deny saft
    ufw deny ftps-data
    ufw deny ftps
    apt-get purge vsftpd -y  -qq
    echo "vsFTPd has been removed. ftp, sftp, saft, ftps-data, and ftps ports have been denied on the firewall."
    elif [ $ftpYN == y ]
    then
    ufw allow ftp
    ufw allow sftp
    ufw allow saft
    ufw allow ftps-data
    ufw allow ftps
    cp /etc/vsftpd/vsftpd.conf /home/$MainUser/backups/
    cp /etc/vsftpd.conf /home/$MainUser/backups/
    gedit /etc/vsftpd/vsftpd.conf&gedit /etc/vsftpd.conf
    service vsftpd restart
    echo "ftp, sftp, saft, ftps-data, and ftps ports have been allowed on the firewall. vsFTPd service has been restarted."
    else
    echo Response not recognized.
    fi
    echo "FTP is complete."
    clear
    if [ $sshYN == n ]
    then
    ufw deny ssh
    apt-get purge openssh-server -y  -qq
    echo "SSH port has been denied on the firewall. Open-SSH has been removed."
    elif [ $sshYN == y ]
    then
    apt-get install openssh-server -y  -qq
    ufw allow ssh
    sudo sed -ir 's/^(PermitRootLogin) .+/\1 no/' /etc/ssh/sshd_config
    sudo sed -ir 's/^#?(PasswordAuthentication) .+/\1 yes/' /etc/ssh/sshd_config
    sudo apt-get install fail2ban
    sudo sed -ir 's/^(Port) .+/\1 12345/' /etc/ssh/sshd_config
    cp /etc/ssh/sshd_config /home/$MainUser/backups/
    echo Type all user account names, with a space in between
    read usersSSH
    echo -e "# Package generated configuration file\n# See the sshd_config(5) manpage for details\n\n# What ports, IPs and protocols we listen for\nPort 2200\n# Use these options to restrict which interfaces/protocols sshd will bind to\n#ListenAddress ::\n#ListenAddress 0.0.0.0\nProtocol 2\n# HostKeys for protocol version \nHostKey /etc/ssh/ssh_host_rsa_key\nHostKey /etc/ssh/ssh_host_dsa_key\nHostKey /etc/ssh/ssh_host_ecdsa_key\nHostKey /etc/ssh/ssh_host_ed25519_key\n#Privilege Separation is turned on for security\nUsePrivilegeSeparation yes\n\n# Lifetime and size of ephemeral version 1 server key\nKeyRegenerationInterval 3600\nServerKeyBits 1024\n\n# Logging\nSyslogFacility AUTH\nLogLevel VERBOSE\n\n# Authentication:\nLoginGraceTime 60\nPermitRootLogin no\nStrictModes yes\n\nRSAAuthentication yes\nPubkeyAuthentication yes\n#AuthorizedKeysFile	%h/.ssh/authorized_keys\n\n# Don't read the user's ~/.rhosts and ~/.shosts files\nIgnoreRhosts yes\n# For this to work you will also need host keys in /etc/ssh_known_hosts\nRhostsRSAAuthentication no\n# similar for protocol version 2\nHostbasedAuthentication no\n# Uncomment if you don't trust ~/.ssh/known_hosts for RhostsRSAAuthentication\n#IgnoreUserKnownHosts yes\n\n# To enable empty passwords, change to yes (NOT RECOMMENDED)\nPermitEmptyPasswords no\n\n# Change to yes to enable challenge-response passwords (beware issues with\n# some PAM modules and threads)\nChallengeResponseAuthentication yes\n\n# Change to no to disable tunnelled clear text passwords\nPasswordAuthentication no\n\n# Kerberos options\n#KerberosAuthentication no\n#KerberosGetAFSToken no\n#KerberosOrLocalPasswd yes\n#KerberosTicketCleanup yes\n\n# GSSAPI options\n#GSSAPIAuthentication no\n#GSSAPICleanupCredentials yes\n\nX11Forwarding no\nX11DisplayOffset 10\nPrintMotd no\nPrintLastLog no\nTCPKeepAlive yes\n#UseLogin no\n\nMaxStartups 2\n#Banner /etc/issue.net\n\n# Allow client to pass locale environment variables\nAcceptEnv LANG LC_*\n\nSubsystem sftp /usr/lib/openssh/sftp-server\n\n# Set this to 'yes' to enable PAM authentication, account processing,\n# and session processing. If this is enabled, PAM authentication will\n# be allowed through the ChallengeResponseAuthentication and\n# PasswordAuthentication.  Depending on your PAM configuration,\n# PAM authentication via ChallengeResponseAuthentication may bypass\n# the setting of \"PermitRootLogin without-password\".\n# If you just want the PAM account and session checks to run without\n# PAM authentication, then enable this but set PasswordAuthentication\n# and ChallengeResponseAuthentication to 'no'.\nUsePAM yes\n\nAllowUsers $usersSSH\nDenyUsers\nRhostsAuthentication no\nClientAliveInterval 300\nClientAliveCountMax 0\nVerifyReverseMapping yes\nAllowTcpForwarding no\nUseDNS no\nPermitUserEnvironment no" > /etc/ssh/sshd_config
    service ssh restart
    sudo /etc/init.d/ssh restart
    mkdir ~/.ssh
    chmod 744 ~/.ssh
    ssh-keygen -t rsa
    echo "SSH port has been allowed on the firewall. SSH config file has been configured. SSH RSA 2048 keys have been created."
    else
    echo Response not recognized.
    fi
    echo "SSH is complete."

    clear
    if [ $telnetYN == n ]
    then
    ufw deny telnet
    ufw deny rtelnet
    ufw deny telnets
    apt-get purge telnet -y  -qq
    apt-get purge telnetd -y  -qq
    apt-get purge inetutils-telnetd -y  -qq
    apt-get purge telnetd-ssl -y  -qq
    echo "Telnet port has been denied on the firewall and Telnet has been removed."
    elif [ $telnetYN == y ]
    then
    ufw allow telnet
    ufw allow rtelnet
    ufw allow telnets
    echo "Telnet port has been allowed on the firewall."
    else
    echo Response not recognized.
    fi
    echo "Telnet is complete."



    clear
    if [ $mailYN == n ]
    then
    ufw deny smtp
    ufw deny pop2
    ufw deny pop3
    ufw deny imap2
    ufw deny imaps
    ufw deny pop3s
    echo "smtp, pop2, pop3, imap2, imaps, and pop3s ports have been denied on the firewall."
    elif [ $mailYN == y ]
    then
    ufw allow smtp
    ufw allow pop2
    ufw allow pop3
    ufw allow imap2
    ufw allow imaps
    ufw allow pop3s
    echo "smtp, pop2, pop3, imap2, imaps, and pop3s ports have been allowed on the firewall."
    else
    echo Response not recognized.
    fi
    echo "Mail is complete."



    clear
    if [ $printYN == n ]
    then
    ufw deny ipp
    ufw deny printer
    ufw deny cups
    echo "ipp, printer, and cups ports have been denied on the firewall."
    elif [ $printYN == y ]
    then
    ufw allow ipp
    ufw allow printer
    ufw allow cups
    echo "ipp, printer, and cups ports have been allowed on the firewall."
    else
    echo Response not recognized.
    fi
    echo "Printing is complete."



    clear
    if [ $dbYN == n ]
    then
    ufw deny ms-sql-s
    ufw deny ms-sql-m
    ufw deny mysql
    ufw deny mysql-proxy
    apt-get purge mysql -y  -qq
    apt-get purge mysql-client-core-5.5 -y  -qq
    apt-get purge mysql-client-core-5.6 -y  -qq
    apt-get purge mysql-common-5.5 -y  -qq
    apt-get purge mysql-common-5.6 -y  -qq
    apt-get purge mysql-server -y  -qq
    apt-get purge mysql-server-5.5 -y  -qq
    apt-get purge mysql-server-5.6 -y  -qq
    apt-get purge mysql-client-5.5 -y  -qq
    apt-get purge mysql-client-5.6 -y  -qq
    apt-get purge mysql-server-core-5.6 -y  -qq
    echo "ms-sql-s, ms-sql-m, mysql, and mysql-proxy ports have been denied on the firewall. MySQL has been removed."
    elif [ $dbYN == y ]
    then
    ufw allow ms-sql-s
    ufw allow ms-sql-m
    ufw allow mysql
    ufw allow mysql-proxy
    apt-get install mysql-server-5.6 -y  -qq
    cp /etc/my.cnf /home/$MainUser/backups/
    cp /etc/mysql/my.cnf /home/$MainUser/backups/
    cp /usr/etc/my.cnf /home/$MainUser/backups/
    cp ~/.my.cnf /home/$MainUser/backups/
    if grep -q "bind-address" "/etc/mysql/my.cnf"
    then
    	sed -i "s/bind-address\t\t=.*/bind-address\t\t= 127.0.0.1/g" /etc/mysql/my.cnf
    fi
    gedit /etc/my.cnf&gedit /etc/mysql/my.cnf&gedit /usr/etc/my.cnf&gedit ~/.my.cnf
    service mysql restart
    echo "ms-sql-s, ms-sql-m, mysql, and mysql-proxy ports have been allowed on the firewall. MySQL has been installed. MySQL config file has been secured. MySQL service has been restarted."
    else
    echo Response not recognized.
    fi
    echo "MySQL is complete."



    clear
    if [ $httpYN == n ]
    then
    ufw deny http
    ufw deny https
    apt-get purge apache2 -y  -qq
    rm -r /var/www/*
    echo "http and https ports have been denied on the firewall. Apache2 has been removed. Web server files have been removed."
    elif [ $httpYN == y ]
    then
    apt-get install apache2 -y  -qq
    ufw allow http
    ufw allow https
    cp /etc/apache2/apache2.conf /home/$MainUser/backups/
    if [ -e /etc/apache2/apache2.conf ]
    then
    	  echo -e '\<Directory \>\n\t AllowOverride None\n\t Order Deny,Allow\n\t Deny from all\n\<Directory \/\>\nUserDir disabled root' >> /etc/apache2/apache2.conf
    fi
    chown -R root:root /etc/apache2

    echo "http and https ports have been allowed on the firewall. Apache2 config file has been configured. Only root can now access the Apache2 folder."
    else
    echo Response not recognized.
    fi
    echo "Web Server is complete."



    clear
    if [ $dnsYN == n ]
    then
    ufw deny domain
    apt-get purge bind9 -qq
    echo "domain port has been denied on the firewall. DNS name binding has been removed."
    elif [ $dnsYN == y ]
    then
    ufw allow domain
    echo "domain port has been allowed on the firewall."
    else
    echo Response not recognized.
    fi
    echo "DNS is complete."
    clear
    if [ $mediaFilesYN == n ]
    then
    find / -name "*.midi" -type f
    find / -name "*.mid" -type f
    find / -name "*.mod" -type f
    find / -name "*.mp3" -type f
    find / -name "*.mp2" -type f
    find / -name "*.mpa" -type f
    find / -name "*.abs" -type f
    find / -name "*.mpega" -type f
    find / -name "*.au" -type f
    find / -name "*.snd" -type f
    find / -name "*.wav" -type f
    find / -name "*.aiff" -type f
    find / -name "*.aif" -type f
    find / -name "*.sid" -type f
    find / -name "*.flac" -type f
    find / -name "*.ogg" -type f
    clear
    echo "All audio files has been listed."

    find / -name "*.mpeg" -type f
    find / -name "*.mpg" -type f
    find / -name "*.mpe" -type f
    find / -name "*.dl" -type f
    find / -name "*.movie" -type f
    find / -name "*.movi" -type f
    find / -name "*.mv" -type f
    find / -name "*.iff" -type f
    find / -name "*.anim5" -type f
    find / -name "*.anim3" -type f
    find / -name "*.anim7" -type f
    find / -name "*.avi" -type f
    find / -name "*.vfw" -type f
    find / -name "*.avx" -type f
    find / -name "*.fli" -type f
    find / -name "*.flc" -type f
    find / -name "*.mov" -type f
    find / -name "*.qt" -type f
    find / -name "*.spl" -type f
    find / -name "*.swf" -type f
    find / -name "*.dcr" -type f
    find / -name "*.dir" -type f
    find / -name "*.dxr" -type f
    find / -name "*.rpm" -type f
    find / -name "*.rm" -type f
    find / -name "*.smi" -type f
    find / -name "*.ra" -type f
    find / -name "*.ram" -type f
    find / -name "*.rv" -type f
    find / -name "*.wmv" -type f
    find / -name "*.asf" -type f
    find / -name "*.asx" -type f
    find / -name "*.wma" -type f
    find / -name "*.wax" -type f
    find / -name "*.wmv" -type f
    find / -name "*.wmx" -type f
    find / -name "*.3gp" -type f
    find / -name "*.mov" -type f
    find / -name "*.mp4" -type f
    find / -name "*.avi" -type f
    find / -name "*.swf" -type f
    find / -name "*.flv" -type f
    find / -name "*.m4v" -type f
    clear
    echo "All video files have been listed."

    find / -name "*.tiff" -type f
    find / -name "*.tif" -type f
    find / -name "*.rs" -type f
    find / -name "*.im1" -type f
    find / -name "*.gif" -type f
    find / -name "*.jpeg" -type f
    find / -name "*.jpg" -type f
    find / -name "*.jpe" -type f
    find / -name "*.png" -type f
    find / -name "*.rgb" -type f
    find / -name "*.xwd" -type f
    find / -name "*.xpm" -type f
    find / -name "*.ppm" -type f
    find / -name "*.pbm" -type f
    find / -name "*.pgm" -type f
    find / -name "*.pcx" -type f
    find / -name "*.ico" -type f
    find / -name "*.svg" -type f
    find / -name "*.svgz" -type f
    clear
    echo "All image files have been listed."
    else
    echo Response not recognized.
    fi
    echo "Media files are complete."


}
BASICCIS2(){
    clear
    echo "Created by Matthew Bierman, Lightning McQueens, Faith Lutheran Middle & High School, Las Vegas, NV, USA"
    echo "Last Modified on Friday, January 21st, 2016, 7:20am"
    echo "Linux Ubuntu Script"
    unalias -a
    echo "All alias have been removed."
    read -p "Next: "

    clear
    usermod -L root
    echo "Root account has been locked. Use 'usermod -U root' to unlock it."
    read -p "Next: "

    clear
    chmod 640 ~/.bash_history
    echo "Bash history file permissions set."
    read -p "Next: "


    clear
    chmod 640 /etc/shadow
    echo "Read/Write permissions on shadow have been set."
    read -p "Next: "

    clear
    echo "Check for any user folders that do not belong to any users in /home/."
    ls -a /home/ >> Script.log
    read -p "Next: "


    clear
    echo "Check for any files for users that should not be administrators in /etc/sudoers.d."
    cat /etc/sudoers
    echo "If it does not say root and admin or says anything more, call me. DO NOT ATTEMPT SUDOERS IF YOU ARE NOT ME."
    ls -a /etc/sudoers.d >> Script.log
    read -p "Next: "


    clear
    cp /etc/rc.local /home/$MainUser/backups/
    echo > /etc/rc.local
    echo 'exit 0' >> /etc/rc.local
    echo "Any startup scripts have been removed."
    read -p "Next: "


    clear
    apt-get install ufw -y  -qq
    ufw enable
    ufw deny 1337
    echo "Firewall enabled and port 1337 blocked."
    read -p "Next: "


    clear
    env x='() { :;}; echo vulnerable' bash -c "echo this is a test"
    read -p "If it says vulnerable, enter y" a
    if [ $a = y ]
    then
    sudo apt-get install --only-upgrade bash
    fi
    sudo apt-get install --only-upgrade bash
    echo "Shellshock Bash vulnerability has been fixed."
    read -p "Next: "


    clear
    chmod 777 /etc/hosts
    cp /etc/hosts /home/$MainUser/backups/
    echo > /etc/hosts
    echo -e "127.0.0.1 ubuntu\n127.0.0.1 localhost\n127.0.1.1 $USER\n::1 ip6-localhost ip6-loopback\nfe00::0 ip6-localnet\nff00::0 ip6-mcastprefix\nff02::1 ip6-allnodes\nff02::2 ip6-allrouters" >> /etc/hosts
    chmod 644 /etc/hosts
    echo "HOSTS file has been set to defaults."
    read -p "Next: "


    clear
    sudo apt-get install lightdm
    chmod 777 /etc/lightdm/lightdm.conf
    cp /etc/lightdm/lightdm.conf /home/$MainUser/backups/
    echo > /etc/lightdm/lightdm.conf
    echo -e '[SeatDefaults]\nallow-guest=false\ngreeter-hide-users=true\ngreeter-show-manual-login=true' >> /etc/lightdm/lightdm.conf
    chmod 644 /etc/lightdm/lightdm.conf
    echo "LightDM has been secured."
    read -p "Next: "


    clear
    find /bin/ -name "*.sh" -type f -delete
    echo "Scripts in bin have been removed."
    read -p "Next: "


    clear
    cp /etc/default/irqbalance /home/$MainUser/backups/
    echo > /etc/default/irqbalance
    echo -e "#Configuration for the irqbalance daemon\n\n#Should irqbalance be enabled?\nENABLED=\"0\"\n#Balance the IRQs only once?\nONESHOT=\"0\"" >> /etc/default/irqbalance
    echo "IRQ Balance has been disabled."
    read -p "Next: "


    clear
    cp /etc/sysctl.conf /home/$MainUser/backups/
    echo > /etc/sysctl.conf
    echo -e "# Controls IP packet forwarding\nnet.ipv4.ip_forward = 0\n\n# IP Spoofing protection\nnet.ipv4.conf.all.rp_filter = 1\nnet.ipv4.conf.default.rp_filter = 1\n\n# Ignore ICMP broadcast requests\nnet.ipv4.icmp_echo_ignore_broadcasts = 1\n\n# Disable source packet routing\nnet.ipv4.conf.all.accept_source_route = 0\nnet.ipv6.conf.all.accept_source_route = 0\nnet.ipv4.conf.default.accept_source_route = 0\nnet.ipv6.conf.default.accept_source_route = 0\n\n# Ignore send redirects\nnet.ipv4.conf.all.send_redirects = 0\nnet.ipv4.conf.default.send_redirects = 0\n\n# Block SYN attacks\nnet.ipv4.tcp_syncookies = 1\nnet.ipv4.tcp_max_syn_backlog = 2048\nnet.ipv4.tcp_synack_retries = 2\nnet.ipv4.tcp_syn_retries = 5\n\n# Log Martians\nnet.ipv4.conf.all.log_martians = 1\nnet.ipv4.icmp_ignore_bogus_error_responses = 1\n\n# Ignore ICMP redirects\nnet.ipv4.conf.all.accept_redirects = 0\nnet.ipv6.conf.all.accept_redirects = 0\nnet.ipv4.conf.default.accept_redirects = 0\nnet.ipv6.conf.default.accept_redirects = 0\n\n# Ignore Directed pings\nnet.ipv4.icmp_echo_ignore_all = 1\n\n# Accept Redirects? No, this is not router\nnet.ipv4.conf.all.secure_redirects = 0\n\n# Log packets with impossible addresses to kernel log? yes\nnet.ipv4.conf.default.secure_redirects = 0\n\n########## IPv6 networking start ##############\n# Number of Router Solicitations to send until assuming no routers are present.\n# This is host and not router\nnet.ipv6.conf.default.router_solicitations = 0\n\n# Accept Router Preference in RA?\nnet.ipv6.conf.default.accept_ra_rtr_pref = 0\n\n# Learn Prefix Information in Router Advertisement\nnet.ipv6.conf.default.accept_ra_pinfo = 0\n\n# Setting controls whether the system will accept Hop Limit settings from a router advertisement\nnet.ipv6.conf.default.accept_ra_defrtr = 0\n\n#router advertisements can cause the system to assign a global unicast address to an interface\nnet.ipv6.conf.default.autoconf = 0\n\n#how many neighbor solicitations to send out per address?\nnet.ipv6.conf.default.dad_transmits = 0\n\n# How many global unicast IPv6 addresses can be assigned to each interface?
    net.ipv6.conf.default.max_addresses = 1\n\n########## IPv6 networking ends ##############" >> /etc/sysctl.conf
    sysctl -p >> /dev/null
    echo "Sysctl has been configured."
}
BASICCIS() {
    BASICCIS2
    BASICCIS3
}
sys() {
	sed -i '$a net.ipv6.conf.all.disable_ipv6 = 1' /etc/sysctl.conf
	sed -i '$a net.ipv6.conf.default.disable_ipv6 = 1' /etc/sysctl.conf
	sed -i '$a net.ipv6.conf.lo.disable_ipv6 = 1' /etc/sysctl.conf

	sed -i '$a net.ipv4.conf.all.rp_filter=1' /etc/sysctl.conf

	sed -i '$a net.ipv4.conf.all.accept_source_route=0' /etc/sysctl.conf

	sed -i '$a net.ipv4.tcp_max_syn_backlog = 2048' /etc/sysctl.conf
	sed -i '$a net.ipv4.tcp_synack_retries = 2' /etc/sysctl.conf
	sed -i '$a net.ipv4.tcp_syn_retries = 5' /etc/sysctl.conf
	sed -i '$a net.ipv4.tcp_syncookies=1' /etc/sysctl.conf

	sed -i '$a net.ipv4.ip_foward=0' /etc/sysctl.conf
	sed -i '$a net.ipv4.conf.all.send_redirects=0' /etc/sysctl.conf
	sed -i '$a net.ipv4.conf.default.send_redirects=0' /etc/sysctl.conf
    sysctl -w net.ipv4.tcp_syncookies=1
	sysctl -w net.ipv4.ip_forward=0
	sysctl -w net.ipv4.conf.all.send_redirects=0
	sysctl -w net.ipv4.conf.default.send_redirects=0
	sysctl -w net.ipv4.conf.all.accept_redirects=0
	sysctl -w net.ipv4.conf.default.accept_redirects=0
	sysctl -w net.ipv4.conf.all.secure_redirects=0
	sysctl -w net.ipv4.conf.default.secure_redirects=0
	sysctl -p

}
sysSCAN(){
    echo "Scanning for Viruses..."
	echo "Starting CHKROOTKIT scan..."
	chkrootkit -q
	echo "Starting RKHUNTER scan..."
	rkhunter --update
	rkhunter --propupd #Run this once at install
	rkhunter -c --enable all --disable none
	echo "Starting CLAMAV scan..."
	systemctl stop clamav-freshclam
	freshclam --stdout
	systemctl start clamav-freshclam
	clamscan -r --bell -i /


}

proc() {
	lsof -Pnl +M -i > runningProcesses.log
	sed -i '/avahi-dae/ d' runningProcesses.log
	sed -i '/cups-brow/ d' runningProcesses.log
	sed -i '/dhclient/ d' runningProcesses.log
	sed -i '/dnsmasq/ d' runningProcesses.log
	sed -i '/cupsd/ d' runningProcesses.log
    cat runningProcesses.log

}
linPEAS(){
    curl https:/raw.githubusercontent.com/carlospolop/privilege-escalation-awesome-scripts-suite/master/linPEAS/linpeas.sh | sh
    ./linpeas.sh >> Output.log
}
nc(){

grep -i 'nc|netcat'
if [ $? -eq 0 ]
then
	cat runningProcesses.log
		read -p "What is the name of the suspected netcat?[none]: " nc
			if [ $nc == "none"]
			then
				echo "uh ok lol"
			else
				whereis $nc > Path
				ALIAS=`alias | grep nc | cut -d' ' -f2 | cut -d'=' -f1`
				PID=`pgrep $nc`
				for path in `cat Path`
				do
						echo $path
						if [ $? -eq 0 ]
						then
								sed -i 's/^/#/' $path
								kill $PID
                                echo "Netcat has been eliminated."
						else
								echo "This is not a netcat process."
						fi
				done
			fi

			ls /etc/init | grep $nc.conf >> /dev/null
			if [ $? -eq 0 ]
			then
					cat /etc/init/$nc.conf | grep -E -i 'nc|netcat|$ALIAS' >> /dev/null
					if [ $? -eq 0 ]
					then
							sed -i 's/^/#/' /etc/init/$nc.conf
							kill $PID
                            echo "Netcat has been eliminated."
					else
							echo "This is not a netcat process."
					fi
			fi

			ls /etc/init.d | grep $nc >>/dev/null
			if [ $? -eq 0 ]
			then
					cat /etc/init.d/$nc | grep -E -i 'nc|netcat|$ALIAS' >> /dev/null
					if [ $? -eq 0 ]
					then
							sed -i 's/^/#/' /etc/init.d/$nc
							kill $PID
                            echo "Netcat has been eliminated."
					else
							echo "This is not a netcat process."
					fi
			fi

			ls /etc/cron.d | grep $nc >>/dev/null
			if [ $? -eq 0 ]
			then
					cat /etc/cron.d/$nc | grep -E -i 'nc|netcat|$ALIAS' >> /dev/null
					if [ $? -eq 0 ]
					then
							sed -i 's/^/#/' /etc/init.d/$nc
							kill $PID
					else
							echo "This is not a netcat process."
					fi
			fi

			ls /etc/cron.hourly | grep $nc >>/dev/null
			if [ $? -eq 0 ]
			then
					cat /etc/cron.hourly/$nc | grep -E -i 'nc|netcat|$ALIAS' >> /dev/null
					if [ $? -eq 0 ]
					then
							sed -i 's/^/#/' /etc/init.d/$nc
							kill $PID
                            echo "Netcat has been eliminated"
					else
							echo "This is not a netcat process."
					fi
			fi

			for x in $(ls /var/spool/cron/crontabs)
			do
				cat $x | grep '$nc|nc|netcat|$ALIAS'
				if [ $? -eq 0 ]
				then
					sed -i 's/^/#/' /var/spool/cron/crontabs/$x
					kill $PID
                    echo "Netcat has been found and eliminated in $x crontabs"
				else
					echo "netcat has not been found in $x crontabs."
				fi
			done

			cat /etc/crontab | grep -i 'nc|netcat|$ALIAS'
			if [ $? -eq 0 ]
			then
				echo "NETCAT FOUND IN CRONTABS! GO AND REMOVE!!!!!!!!!!"
			fi
			echo "Uninstalling netcat now."

			apt-get autoremove --purge netcat netcat-openbsd netcat-traditional
else
	echo "Netcat is not installed"
fi
    clear
    apt-get purge netcat -y  -qq
    apt-get purge netcat-openbsd -y  -qq
    apt-get purge netcat-traditional -y  -qq
    apt-get purge ncat -y  -qq
    apt-get purge pnetcat -y  -qq
    apt-get purge socat -y  -qq
    apt-get purge sock -y  -qq
    apt-get purge socket -y  -qq
    apt-get purge sbd -y  -qq
    rm /usr/bin/nc
    clear

}
ListShares(){
    echo "Samba shares: "
    smbclient -L localhost
    read -p "Other shares: "
    gvfs-mount -l -i

}
To-DoList(){
    read -p "Ensure that you have points for upgrading the kernel, each service specified in the readme, and bash if it is vulnerable to shellshock."
    read -p "Search for other files, for stuff like passwds or credit card info"
    read -p "If netshares are a thing search them for unauthorized ones"
    read -p "Configure & update services"
    read -p "CIS TIME LOL ENJOY"

}
txtSearch(){
    echo "Txt and zip files: "
    find / -name "*.txt" -type f
    find / -name "*.zip" -type f
    read -p "What file type (type only name search is next): *." File
    find / -name "*.$File" -type f
    read -p "What filename: " File2
    find / -iname "$File2"

}
sudoers() {

	cat /etc/sudoers | grep NOPASSWD.* >> /dev/null
	if [ $? -eq 0 ]
	then
		echo "NOPASSWD VALUE HAS BEEN FOUND IN THE SUDOERS FILE, GO CHANGE IT." >> postScript.log
	fi
	cat /etc/sudoers | grep timestamp_timeout >> /dev/null
	if [ $? -eq 0 ]
	then
		TIME=`cat /etc/sudoers | grep timestamp_timeout | cut -f2 | cut -d= -f2`
		echo "## Time out value has been set to $TIME Please go change it or remove it." >> postScript
	fi
    cat /etc/sudoers

}
firefoxConf(){
    read -p "What is the filepath of the new user.js(should end with user.js): " aFilePath
    ls /home/$MainUser/.mozilla/firefox/
    read -p "What is your profile name (should be xxxxx.default or smthng like that): " ProfileName
    cp $aFilePath /home/$MainUser/.mozilla/firefox/$ProfileName

}
cron() {
    touch cron.log
	echo "###CRONTABS###" > cron.log
	for x in $(awk -F: '($3>=1000)&&($1!="nobody"){print $1}' /etc/passwd)
    do
        echo "$x's crontabs are: "
    crontab -u $x -l | grep -v "^#"
    done
    read -p "Above is the list of all crontabs"
	echo "###CRON JOBS###" >> cron.log
	ls /etc/cron.* >> cron.log
	ls /var/spool/cron/crontabs/.* >> cron.log
	ls /etc/crontab >> cron.log
	echo "###Init.d###" >> cron.log
	ls /etc/init.d >> cron.log
	echo "###Init###" >> cron.log
	ls /etc/init >> cron.log
	cat cron.log
    echo "Configuring cron"
    crontab -r
	cd /etc/
	/bin/rm -f cron.deny at.deny
	echo root >cron.allow
	echo root >at.allow
	/bin/chown root:root cron.allow at.allow
	/bin/chmod 644 cron.allow at.allow
    sudo chown -R root:root /etc/*cron*
    sudo chmod -R 600 /etc/*cron*
    sudo chown -R root:root /var/spool/cron
    sudo chmod -R 600 /var/spool/cron
    read -p "Next up is opening root crontabs in nano so you can inspect and remove (or add) cron jobs"
    nano /etc/crontab
    echo "List of all crontab files"
    find /etc -type f -iname *cron*
    find /etc -type f -iname *crontab
    read -p "Continue: "

}
runFull(){
    update
    autoUpdate
    pFiles
    configureFirewall
    loginConf
    createUser
    chgPasswd
    delUser
    admin
    cron
    passPol
    lockoutPol
    hakTools
    sshd
    sys
    sudoers
    proc
    nc
    reboot
    secRoot
    CAD
    BASICCIS
    To-DoList
}
CAD() {
	systemctl mask ctrl-alt-del.target
    systemctl disable ctrl-alt-del.target
    systemctl stop ctrl-alt-del.target
    sudo service ctrl-alt-del.target stop
    systemctl daemon-reload

}
chgUID(){
    e=$(awk -F: '{print $3}' /etc/passwd)
    echo "Uids: $e"
    for x in `cut -d: -f1,3 /etc/passwd | egrep ':[0]{1}$' | cut -d: -f1`
    do
        read -p "Is the $x root, or the equivalent to root?" isroot
        if [ $isroot == n ]
        then

            read -p "New UID: " newuid
            usermod -u $newuid $x
        fi
    done
    cut -f3 -d":" /etc/passwd | sort -n | uniq -c | while read x ; do [ -z "$x" ] && break ##test following
    set - $x
    if [ $1 -gt 1 ]; then
        users=$(awk -F: '($3 == n) { print $1 }' n=$2 /etc/passwd | xargs)
        echo "Duplicate UID ($2): $users"
        read -p "New UID: " newuid
        usermod -u $newuid ${users[0]}
    fi
    done

}
AppsServicesAuditing(){
    sudo apt-get install synaptic
    sudo apt-get install apt-xapian-index
    sudo synaptic
    read -p "Next: "
    sudo apt-get install auditd
    auditctl -e 1
    read -p "Next: "
    sudo apt-get install bum
    sudo bum

}
ManualStuff(){
    echo "Manual checks"
    echo "Hosts file: "
    echo "Check doc for correct output"
    echo "https:/docs.google.com/document/d/1bEgITm6sw3Ljtzhh1nhmbhqsEKYQ0YgWJL_FMAepdk0/edit#"
    cat /etc/hosts
    read -p "Next: "
    echo "Sudoers file: "
    cat /etc/sudoers
    read -p "Next: "
    echo "Auditors file"
    cat /etc/audit.d/auditd.conf
    echo "Idk what this is supposed to look like, if sus then k den"
    read -p "Next, ports: "
    lsof -i -n -P
	netstat -punta
    read -p "Next, resolv.conf: "
    echo "Reslov.conf make sure if safe, use 8.8.8.8 for name server"
    nano /etc/resolv.conf

}
SysConf(){
    sudo apt-get install auditd -y
    echo "Securing boot/grub"
    sudo chown root:root /boot/grub
    sudo chmod 744 /boot/grub
    rmmod cramfs
    rmmod freevxfs
    rmmod jffs2
    rmmod hfs
    rmmod hfsplus
    rmmod udf

    systemctl is-enabled autofs

    aideinit

    sudo chmod 702 /etc/pam.d/common-auth
    echo "auth required pam_tally2.so file=/var/log/tallylog deny=5 even_deny_root\ unlock_time=900" >> /etc/pam.d/common-auth
    sudo chmod 744 /etc/pam.d/common-auth

    sudo auditctl -e 1

    sudo chmod 702 /etc/sysctl.conf
    echo "net.ipv4.conf.default.rp_filter = 1" >> /etc/sysctl.conf
    echo "net.ipv4.conf.all.rp_filter = 1" >> /etc/sysctl.conf
    echo "net.ipv4.tcp_syncookies = 1" >> /etc/sysctl.conf
    echo "net.ipv4.tcp_max_syn_backlog = 2048" >> /etc/sysctl.conf
    echo "net.ipv4.tcp_synack_retries = 2" >> /etc/sysctl.conf
    echo "net.ipv4.tcp_syn_retries = 5" >> /etc/sysctl.conf
    echo "net.ipv4.ip_forward = 0" >> /etc/sysctl.conf
    echo "net.ipv4.conf.all.accept_redirects = 0" >> /etc/sysctl.conf
    echo "net.ipv6.conf.all.accept_redirects = 0" >> /etc/sysctl.conf
    echo "net.ipv4.conf.default.accept_redirects = 0" >> /etc/sysctl.conf
    echo "net.ipv6.conf.default.accept_redirects = 0" >> /etc/sysctl.conf
    echo "net.ipv4.conf.all.send_redirects = 0" >> /etc/sysctl.conf
    echo "net.ipv4.conf.default.send_redirects = 0" >> /etc/sysctl.conf
    echo "net.ipv4.conf.all.accept_source_route = 0" >> /etc/sysctl.conf
    echo "net.ipv6.conf.all.accept_source_route = 0" >> /etc/sysctl.conf
    echo "net.ipv4.conf.default.accept_source_route = 0" >> /etc/sysctl.conf
    echo "net.ipv6.conf.default.accept_source_route = 0" >> /etc/sysctl.conf
    echo "net.ipv4.conf.all.log_martians = 1" >> /etc/sysctl.conf
    echo "net.ipv4.icmp_ignore_bogus_error_responses = 1" >> /etc/sysctl.conf
    echo "net.ipv4.icmp_echo_ignore_broadcasts = 1" >> /etc/sysctl.conf
    echo "net.ipv4.icmp_echo_ignore_all = 1" >> /etc/sysctl.conf
    echo "kernel.exec-shield = 1" >> /etc/sysctl.conf
    echo "kernel.randomize_va_space = 1" >> /etc/sysctl.conf
    echo "net.ipv6.conf.all.disable_ipv6 = 1" >> /etc/sysctl.conf
    echo "net.ipv6.conf.default.disable_ipv6 = 1" >> /etc/sysctl.conf
    echo "net.ipv6.conf.lo.disable_ipv6 = 1" >> /etc/sysctl.conf
    echo "net.ipv4.conf.all.secure_redirects = 0" >> /etc/sysctl.conf
    echo "net.ipv4.conf.default.secure_redirects = 0" >> /etc/sysctl.conf
    echo "net.ipv6.conf.default.router_solicitations = 0" >> /etc/sysctl.conf
    echo "net.ipv6.conf.default.accept_ra_rtr_pref = 0" >> /etc/sysctl.conf
    echo "net.ipv6.conf.default.accept_ra_pinfo = 0" >> /etc/sysctl.conf
    echo "net.ipv6.conf.default.accept_ra_defrtr = 0" >> /etc/sysctl.conf
    echo "net.ipv6.conf.default.autoconf = 0" >> /etc/sysctl.conf
    echo "net.ipv6.conf.default.dad_transmits = 0" >> /etc/sysctl.conf
    echo "net.ipv6.conf.default.max_addresses = 1" >> /etc/sysctl.conf
    echo "net.ipv4.conf.all.send redirects = 0" >> /etc/sysctl.conf
    echo "net.ipv4.conf.all.accept redirects = 0" >> /etc/sysctl.conf
    echo "net.ipv4.conf.all.secure redirects = 0" >> /etc/sysctl.conf
    echo "net.ipv4.conf.all.log martians = 1" >> /etc/sysctl.conf
    echo "net.ipv4.conf.all.rp filter = 1" >> /etc/sysctl.conf
    echo "net.ipv6.conf.all.accept ra = 0" >> /etc/sysctl.conf
    echo "net.ipv6.conf.default.accept_ra = 0" >> /etc/sysctl.conf
    echo "net.ipv6.conf.all.accept redirects = 0" >> /etc/sysctl.conf
    echo "kernel.randomize_va_space = 2" >> /etc/sysctl.conf
    echo "vm.panic_on_oom = 1" >> /etc/sysctl.conf
    echo "kernel.panic = 10" >> /etc/sysctl.conf
    sudo chmod 744 /etc/sysctl.conf
    sudo sysctl -p
    sudo sysctl -w net.ipv4.ip forward=0
    sudo sysctl -w net.ipv4.route.flush=1
    sudo sysctl -w net.ipv4.conf.all.send_redirects=0
    sudo sysctl -w net.ipv4.conf.default.send redirects=0
    sudo sysctl -w net.ipv4.route.flush=1
    sudo sysctl -w net.ipv4.conf.all.accept_source_route=0
    sudo sysctl -w net.ipv4.conf.default.accept source route=0
    sudo sysctl -w net.ipv4.route.flush=1
    sudo sysctl -w net.ipv4.conf.all.accept_redirects=0
    sudo sysctl -w net.ipv4.conf.default.accept redirects=0
    sudo sysctl -w net.ipv4.route.flush=1
    sudo sysctl -w net.ipv4.conf.all.secure_redirects=0
    sudo sysctl -w net.ipv4.conf.default.secure_redirects=0
    sudo sysctl -w net.ipv4.route.flush=1
    sudo sysctl -w net.ipv4.conf.all.log_martians=1
    sudo sysctl -w net.ipv4.conf.default.log martians=1
    sudo sysctl -w net.ipv4.route.flush=1
    sudo sysctl -w net.ipv4.icmp echo ignore broadcasts=1
    sudo sysctl -w net.ipv4.route.flush=1
    sudo sysctl -w net.ipv4.icmp_ignore_bogus_error_responses=1
    sudo sysctl -w net.ipv4.route.flush=1
    sudo sysctl -w net.ipv4.conf.all.rp_filter=1
    sudo sysctl -w net.ipv4.conf.default.rp filter=1
    sudo sysctl -w net.ipv4.route.flush=1
    sudo sysctl -w net.ipv4.tcp syncookies=1
    sudo sysctl -w net.ipv4.route.flush=1
    sudo sysctl -w net.ipv6.conf.all.accept_ra=0
    sudo sysctl -w net.ipv6.conf.default.accept ra=0
    sudo sysctl -w net.ipv6.route.flush=1
    sudo sysctl -w net.ipv6.conf.all.accept_redirects=0
    sudo sysctl -w net.ipv6.conf.default.accept redirects=0
    sudo sysctl -w net.ipv6.route.flush=1
    sudo sysctl -w kernel.randomize_va_space=2
    echo "
    net.ipv4.ip forward=0
    net.ipv4.route.flush=1
    net.ipv4.conf.all.send_redirects=0
    net.ipv4.conf.default.send redirects=0
    net.ipv4.route.flush=1
    net.ipv4.conf.all.accept_source_route=0
    net.ipv4.conf.default.accept source route=0
    net.ipv4.route.flush=1
    net.ipv4.conf.all.accept_redirects=0
    net.ipv4.conf.default.accept redirects=0
    net.ipv4.route.flush=1
    net.ipv4.conf.all.secure_redirects=0
    net.ipv4.conf.default.secure_redirects=0
    net.ipv4.route.flush=1
    net.ipv4.conf.all.log_martians=1
    net.ipv4.conf.default.log martians=1
    net.ipv4.route.flush=1
    net.ipv4.icmp echo ignore broadcasts=1
    net.ipv4.route.flush=1
    net.ipv4.icmp_ignore_bogus_error_responses=1
    net.ipv4.route.flush=1
    net.ipv4.conf.all.rp_filter=1
    net.ipv4.conf.default.rp filter=1
    net.ipv4.route.flush=1
    net.ipv4.tcp syncookies=1
    net.ipv4.route.flush=1
    net.ipv6.conf.all.accept_ra=0
    net.ipv6.conf.default.accept ra=0
    net.ipv6.route.flush=1
    net.ipv6.conf.all.accept_redirects=0
    net.ipv6.conf.default.accept redirects=0
    net.ipv6.route.flush=1
    kernel.randomize_va_space=2
    " >> /etc/sysctl.d
    systemctl disable avahi-daemon
    systemctl disable cups
    systemctl disable isc-dhcp-server
    systemctl disable isc-dhcp-server6
    systemctl disable slapd
    systemctl disable nfs-server
    systemctl disable rpcbind
    systemctl disable bind9
    systemctl disable vsftpd
    systemctl disable apache2
    systemctl disable dovecot
    systemctl disable smbd
    systemctl disable squid
    systemctl disable snmpd
    systemctl disable rsync
    systemctl disable nis

    sudo chmod 702 /etc/host.conf
    echo "order bind,hosts" >> /etc/host.conf
    echo "nospoof on" >> /etc/host.conf
    sudo chmod 744 /etc/host.conf

    sudo chmod 702 /etc/security/limits.conf
    echo "* hard core" >> /etc/security/limits.conf
    sudo chmod 744 /etc/security/limits.conf
    sudo chmod 702 /etc/sysctl.conf
    echo "fs.suid_dumpable = 0" >> /etc/sysctl.conf
    sudo chmod 744 /etc/sysctl.conf
    sudo sysctl -w fs.suid_dumpable=0

    sudo chmod 777 /etc/motd
    echo "This system is for authorized users only. Individual use of this system and/or network without authority, or in excess of your authority, is strictly prohibited." > /etc/motd
    sudo chmod 744 /etc/motd
    sudo chmod 777 /etc/issue
    echo "This system is for the use of authorized users only.  Individuals using this computer system without authority, or in excess of their authority, are subject to having all of their activities on this system monitored and recorded by system personnel.  In the course of monitoring individuals improperly using this system, or in the course of system maintenance, the activities of authorized users may also be monitored.  Anyone using this system expressly consents to such monitoring and is advised that if such monitoring reveals possible evidence of criminal activity, system personnel may provide the evidence of such monitoring to law enforcement officials." > /etc/issue
    sudo chmod 744 /etc/issue
    sudo chmod 777 /etc/issue.net
    echo "This system is for the use of authorized users only.  Individuals using this computer system without authority, or in excess of their authority, are subject to having all of their activities on this system monitored and recorded by system personnel.  In the course of monitoring individuals improperly using this system, or in the course of system maintenance, the activities of authorized users may also be monitored.  Anyone using this system expressly consents to such monitoring and is advised that if such monitoring reveals possible evidence of criminal activity, system personnel may provide the evidence of such monitoring to law enforcement officials." > /etc/issue.net
    sudo chmod 744 /etc/issue.net
    touch /etc/dconf/profile/gdm
    sudo chmod 777 /etc/dconf/profile/gdm
    echo "user-db:user" >> /etc/dconf/profile/gdm
    echo "system-db:gdm" >> /etc/dconf/profile/gdm
    echo "file-db:/usr/share/gdm/greeter-dconf/defaults" >> /etc/dconf/profile/gdm
    sudo chmod 744 /etc/dconf/profile/gdm

    sudo chmod 777 /etc/ntp.conf
    echo "restrict -4 default kod nomodify notrap nopeer noquery" >> /etc/ntp.conf
    echo "restrict -6 default kod nomodify notrap nopeer noquery" >> /etc/ntp.conf
    sudo chmod 744 /etc/ntp.conf

    sudo chmod 777 /etc/hosts.deny
    echo "ALL: ALL" >> /etc/hosts.deny
    sudo chmod 744 /etc/hosts.deny

    sudo chmod 777 /etc/modprobe.d/CIS.conf
    echo "install dccp /bin/true" >> /etc/modprobe.d/CIS.conf
    echo "install sctp /bin/true" >> /etc/modprobe.d/CIS.conf
    echo "install rds /bin/true" >> /etc/modprobe.d/CIS.conf
    echo "install tipc /bin/true" >> /etc/modprobe.d/CIS.conf
    sudo chmod 744 /etc/modprobe.d/CIS.conf

    sudo chmod 777 /etc/audit/auditd.conf
    echo "max_log_file = 16384" >> /etc/audit/auditd.conf
    echo "space_left_action = email" >> /etc/audit/auditd.conf
    echo "action mail acct = root" >> /etc/audit/auditd.conf
    echo "admin_space_left_action = halt" >> /etc/audit/auditd.conf
    echo "max_log_file_action = keep_logs" >> /etc/audit/auditd.conf
    sudo chmod 744 /etc/audit/auditd.conf
    systemctl reload auditd
    sudo chmod 777 /etc/audit/audit.rules
    echo "-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change" >> /etc/audit/audit.rules
    echo "-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time- change" >> /etc/audit/audit.rules
    echo "-a always,exit -F arch=b64 -S clock_settime -k time-change" >> /etc/audit/audit.rules
    echo "-a always,exit -F arch=b32 -S clock_settime -k time-change -w /etc/localtime -p wa -k time-change" >> /etc/audit/audit.rules
    echo "-w /etc/group -p wa -k identity" >> /etc/audit/audit.rules
    echo "-w /etc/passwd -p wa -k identity" >> /etc/audit/audit.rules
    echo "-w /etc/gshadow -p wa -k identity" >> /etc/audit/audit.rules
    echo "-w /etc/shadow -p wa -k identity" >> /etc/audit/audit.rules
    echo "-w /etc/security/opasswd -p wa -k identity" >> /etc/audit/audit.rules
    echo "-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale" >> /etc/audit/audit.rules
    echo "-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale" >> /etc/audit/audit.rules
    echo "-w /etc/issue -p wa -k system-locale" >> /etc/audit/audit.rules
    echo "-w /etc/issue.net -p wa -k system-locale" >> /etc/audit/audit.rules
    echo "-w /etc/hosts -p wa -k system-locale" >> /etc/audit/audit.rules
    echo "-w /etc/sysconfig/network -p wa -k system-locale" >> /etc/audit/audit.rules
    echo "-w /etc/apparmor/ -p wa -k MAC-policy" >> /etc/audit/audit.rules
    echo "-w /etc/apparmor.d/ -p wa -k MAC-policy" >> /etc/audit/audit.rules
    echo "-w /var/log/faillog -p wa -k logins" >> /etc/audit/audit.rules
    echo "-w /var/log/lastlog -p wa -k logins" >> /etc/audit/audit.rules
    echo "-w /var/log/tallylog -p wa -k logins" >> /etc/audit/audit.rules
    echo "-w /var/run/utmp -p wa -k session" >> /etc/audit/audit.rules
    echo "-w /var/log/wtmp -p wa -k logins" >> /etc/audit/audit.rules
    echo "-w /var/log/btmp -p wa -k logins" >> /etc/audit/audit.rules
    echo "-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> /etc/audit/audit.rules
    echo "-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> /etc/audit/audit.rules
    echo "-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> /etc/audit/audit.rules
    echo "-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> /etc/audit/audit.rules
    echo "-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> /etc/audit/audit.rules
    echo "-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> /etc/audit/audit.rules
    echo "-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access" >> /etc/audit/audit.rules
    echo "-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access" >> /etc/audit/audit.rules
    echo "-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access" >> /etc/audit/audit.rules
    echo "-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access" >> /etc/audit/audit.rules
    echo "-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts" >> /etc/audit/audit.rules
    echo "-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts" >> /etc/audit/audit.rules
    echo "-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete" >> /etc/audit/audit.rules
    echo "-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete" >> /etc/audit/audit.rules
    echo "-w /etc/sudoers -p wa -k scope" >> /etc/audit/audit.rules
    echo "-w /etc/sudoers.d/ -p wa -k scope" >> /etc/audit/audit.rules
    echo "-w /var/log/sudo.log -p wa -k actions" >> /etc/audit/audit.rules
    echo "-w /sbin/insmod -p x -k modules" >> /etc/audit/audit.rules
    echo "-w /sbin/rmmod -p x -k modules" >> /etc/audit/audit.rules
    echo "-w /sbin/modprobe -p x -k modules" >> /etc/audit/audit.rules
    echo "-a always,exit -F arch=b64 -S init_module -S delete_module -k modules" >> /etc/audit/audit.rules
    sudo chmod 744 /etc/audit/auditd.conf
    sudo chmod 777 /etc/audit/.rules
    echo "-e 2" >> /etc/audit/.rules
    sudo chmod 744 /etc/audit/.rules

    systemctl enable rsyslog
    sudo chmod 777 /etc/rsyslog.conf
    echo "$FileCreateMode 0640" >> /etc/rsyslog.conf
    sudo chmod 744 /etc/rsyslog.conf
    sudo chmod 777 /etc/rsyslog.d/*.conf
    echo "$FileCreateMode 0640" >> /etc/rsyslog.d/*.conf
    sudo chmod 744 /etc/rsyslog.d/*.conf
    sudo chmod -R g-wx,o-rwx /var/log/*

    systemctl enable cron

    sudo chmod 777 /etc/default/grub
    echo "GRUB_CMDLINE_LINUX="ipv6.disable=1"" >> /etc/default/grub
    echo "GRUB_CMDLINE_LINUX="audit=1"" >> /etc/default/grub
    sudo chmod 744 /etc/default/grub
    update-grub

    sudo useradd -D -f 30
    sudo usermod -g 0 root
    sudo chmod 777 /etc/bash.bashrc
    echo "umask 027" >> /etc/bash.bashrc
    sudo chmod 744 /etc/bash.bashrc
    sudo chmod 777 /etc/profile
    echo "umask027" >> /etc/profile
    echo "TMOUT=600" >> /etc/profile
    sudo chmod 744 /etc/profile
    sudo chmod 777 /etc/profile.d/*.sh
    echo "umask 027" >> /etc/profile.d/*.sh
    sudo chmod 744 /etc/profile.d/*.sh
    sudo chmod 777 /etc/bashrc
    echo "TMOUT=600" >> /etc/bashrc
    sudo chmod 744 /etc/bashrc
    echo "1" > /proc/sys/fs/protected_symlinks
    echo "1" > /proc/sys/fs/protected_hardlinks
    sysctl -w kernel.sysrq=0
    echo "0" > /proc/sys/kernel/sysrq


}
AddToGroup(){
    echo "Groups: "
    cat /etc/group
    echo "Users: "
    for x in `awk -F: '($3>=1000)&&($1!="nobody"){print $1}' /etc/passwd`
    do
        groups $x
    done
    read -p "What group would you like to add a user to: " group
    read -p "Who would you like to add: " userprovided
    sudo usermod -a -G $group $userprovided
    groups $userprovided

}
RemoveFromGroup(){
    echo "Groups: "
    cat /etc/group
    echo "Users: "
    for x in `awk -F: '($3>=1000)&&($1!="nobody"){print $1}' /etc/passwd`
    do
        groups $x
    done
    read -p "What group would you like remove a user from: " group
    read -p "Who would you like to remove: " userprovided
    sudo gpasswd -d $userprovided $group
    groups $userprovided

}
UserLock(){
    for u in $(cat /etc/passwd | grep -vE "/bin/.*sh" | cut -d":" -f1); do passwd -l $u; done
}
Permissions(){
    sudo chown root:root /boot/grub/grub.cfg
    sudo chmod 744 /boot/grub/grub.cfg
    chown root:root /etc/crontab
    chmod og-rwx /etc/crontab
    chown root:root /etc/cron.hourly
    chmod og-rwx /etc/cron.hourly
    chown root:root /etc/cron.daily
    chmod og-rwx /etc/cron.daily
    chown root:root /etc/cron.weekly
    chmod og-rwx /etc/cron.weekly
    chown root:root /etc/cron.monthly
    chmod og-rwx /etc/cron.monthly
    chown root:root /etc/cron.d
    chmod og-rwx /etc/cron.d
    rm /etc/cron.deny
    rm /etc/at.deny
    touch /etc/cron.allow
    touch /etc/at.allow
    chmod og-rwx /etc/cron.allow
    chmod og-rwx /etc/at.allow
    chown root:root /etc/cron.allow
    chown root:root /etc/at.allow
    chown root:root /etc/passwd
    chmod 744 /etc/passwd
    chown root:shadow /etc/shadow
    chmod o-rwx,g-wx /etc/shadow
    chown root:root /etc/group
    chmod 700 /etc/group
    chmod 0644 /etc/group
    chown root:root /etc/group-
    chmod u-x,go-wx /etc/group-
    chown root:shadow /etc/gshadow
    chmod o-rwx,g-rw /etc/gshadow
    chown root:root /etc/passwd-
    chmod u-x,go-wx /etc/passwd-
    chown root:root /etc/shadow-
    chown root:shadow /etc/shadow-
    chmod o-rwx,g-rw /etc/shadow-
    chown root:root /etc/gshadow-
    chown root:shadow /etc/gshadow-
    chmod o-rwx,g-rw /etc/gshadow-
    chown root:root /etc/motd
    chmod 744 /etc/motd
    chown root:root /etc/issue
    chmod 744 /etc/issue
    chown root:root /etc/issue.net
    chmod 744 /etc/issue.net
    chown root:root /etc/hosts.allow
    chmod 744 /etc/hosts.allow
    chown root:root /etc/hosts.deny
    chmod 744 /etc/hosts.deny
    clear
    find / -type f -perm -600 -exec ls -l {} \;
    read -p "600-777 listed above (more perms at top), continue: "
    find / -type f \( -perm -4000 -o -perm -2000 -o -perm -6000 -o -perm -1000 \) -exec ls -l {} \;
    read -p "Files with sticky bit, setuid, or groupuid set"

}
CustomPasswd(){
    read -p "What's the custom passwd: " PASS
    read -p "Who's the user: " x
    echo -e "$PASS\n$PASS" | passwd $x >> output.log
    echo -e "Password for $x has been changed." >> password.log

}
encryption(){
    #INDEV
    cd /
    gpg-zip -c -o TheEntireSYSTEM.gpg /

}
BootPerms(){
    sed -i 's/Enter password: /' grub.txt
    sed -i 's/Reenter password: /' grub.txt
    sed -i 's/PBKDF2 hash of your password is /' grub.txt
    paste -sd "" grub.txt > clip
    cat clip > grub.txt

    sudo chmod 777 /etc/grub.d/00_header
    echo "cat <<EOF" >> /etc/grub.d/00_header
    echo "set superusers="root"" >> /etc/grub.d/00_header
    file1=`cat grub.txt`
    echo "password pbkdf2 root '"$file1"'" >> /etc/grub.d/00_header
    echo "EOF" >> /etc/grub.d/00_header
    sudo chmod 744 /etc/grub.d/00_header
    sudo update-grub

    sudo chmod 777 /etc/default/grub
    sed -i 's/apparmor=0/' /etc/default/grub
    sudo chmod 744 /etc/default/grub

    aa-enforce /etc/apparmor.d/*


}
CISAuto(){
    sudo apt install git -y
    sudo apt install ansible -y
    mkdir /etc/ansible
    sudo sh -c "echo '- src: https://github.com/florianutz/Ubuntu2004-CIS.git' > /etc/ansible/requirements.yml"
    cd /etc/ansible/
    sudo ansible-galaxy install -p /etc/ansible/roles -r /etc/ansible/requirements.yml -c local
    echo "- name: Harden Server" > /etc/ansible/harden.yml
    echo "  hosts: localhost" >> /etc/ansible/harden.yml
    echo "  connection: local" >> /etc/ansible/harden.yml
    echo "  become: yes" >> /etc/ansible/harden.yml
    echo "  roles:" >> /etc/ansible/harden.yml
    echo "    - Ubuntu2004-CIS" >> /etc/ansible/harden.yml
    nano /etc/ansible/roles/Ubuntu2004-CIS/defaults/main.yml
    read -p "Enter y to continue and CIS harden, btw this might kill you : D. Enter anything else to skip to compliance checks" a
    if [ $a = y ]
    then
    sudo ansible-playbook /etc/ansible/harden.yml
    fi
    sudo apt install -y libopenscap8 xsltproc
    sudo wget https://github.com/ComplianceAsCode/content/releases/download/v0.1.43/scap-security-guide-0.1.43-oval-510.zip
    sudo apt install -y unzip
    sudo unzip scap-security-guide-0.1.43-oval-510.zip
    sudo mkdir /etc/oscap
    sudo mkdir /etc/oscap/content
    sudo cp -r scap-security-guide-0.1.43-oval-5.10/* /etc/oscap/content/
    sudo rm -r scap-security-guide-0.1.43-oval-5.10/
    sudo rm scap-security-guide-0.1.43-oval-510.zip
    sudo oscap oval eval --report /etc/oscap/report.html /etc/oscap/content/ssg-ubuntu2004-ds.xml
}
STIGAuto(){
    sudo apt install git -y
    sudo apt install ansible -y
    mkdir /etc/ansible
    sudo sh -c "echo '- src: https://github.com/beholdenkey/ansible-role-ubuntu2004-stig.git' > /etc/ansible/requirements.yml"
    cd /etc/ansible/
    sudo ansible-galaxy install -p /etc/ansible/roles -r /etc/ansible/requirements.yml -c local
    echo "- name: Harden Server" > /etc/ansible/harden2.yml
    echo "  hosts: localhost" >> /etc/ansible/harden2.yml
    echo "  connection: local" >> /etc/ansible/harden2.yml
    echo "  become: yes" >> /etc/ansible/harden2.yml
    echo "  roles:" >> /etc/ansible/harden2.yml
    echo "    - - ansible-role-ubuntu2004-stig" >> /etc/ansible/harden2.yml
    nano /etc/ansible/roles/ansible-role-ubuntu2004-stig/blob/devel/defaults/main.yml
    read -p "Enter y to continue and STIG harden, btw this might kill you : D. Enter anything else to skip to compliance checks" a
    if [ $a = y ]
    then
    sudo ansible-playbook /etc/ansible/harden2.yml
    fi
}
ReadLogs(){
    cat /var/log/auth.log
    read -p "Next: "
    cat /var/log/daemon.log
    read -p "Next: "
    cat /var/log/kern.log
    read -p "Next: "
    cat /var/log/syslog

}
FileMoveForConf(){
    read -p "What's the file path (Like /home/jerry/Desktop/user.js (has filename in it)): " filename
    read -p "Where do we move it: " target
    cp $filename $target

}
DisableRoot(){
    read -p "Disable Root: " a
    if [[ $a = y ]]; then
    	usermod -L root
        echo "If you want to (recommended but risky), go inside /etc/passwd and set root to /usr/sbin/nologin"
    else
        echo "Ok then"
    fi
}
ListConfFiles(){
    find / -name "*.conf" -type f >> configfiles.log
    find / -name "*.rules" -type f >> configfiles.log
    cat configfiles.log
}
show_menu(){
	case "$opsys" in
	"Ubuntu")
				echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
				echo "           ██╗   ██╗██████╗ ██╗   ██╗███╗   ██╗████████╗██╗   ██╗         "
				echo "           ██║   ██║██╔══██╗██║   ██║████╗  ██║╚══██╔══╝██║   ██║         "
				echo "           ██║   ██║██████╔╝██║   ██║██╔██╗ ██║   ██║   ██║   ██║         "
				echo "           ██║   ██║██╔══██╗██║   ██║██║╚██╗██║   ██║   ██║   ██║         "
				echo "           ╚██████╔╝██████╔╝╚██████╔╝██║ ╚████║   ██║   ╚██████╔╝         "
				echo "            ╚═════╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═══╝   ╚═╝    ╚═════╝          "
                echo "~~~~~~~~~~~~~~~~~Created by: Nakul Choudhary 2026 Gang~~~~~~~~~~~~~~~~~~~~"
				echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
				echo " "
                echo "1) Update the machine.(Beginning) 2) Set automatic updates."
				echo "3) Search for prohibited file.	4) configure the firewall."
				echo "5) Configure login screen.		6) Create any new users."
				echo "7) Change all the passwords.		8) Delete any users."
				echo "9) Set all the admins.			10) List all cronjobs."
				echo "11) Set the password policy.		12) Set the lockout policy."
				echo "13) Remove the hacking tools.		14) Configure SSH."
				echo "15) Edit the sysctl.conf.			16) Export the sudoers file."
				echo "17) List all running processes.	18) Remove NetCat."
				echo "19) Reboot the machine.			20) Secure the root"
				echo "21) PostScript				    22) Disable ctrl-alt-del"
				echo "23) BASIC CIS               		(Used for quick pts)"
                echo "24) To do list(Other stuff)   	25) Run full (In dev)"
                echo "26) File search   	            27) Antivirus and defense"
                echo "28) Network/smb shares            29) UID change"
                echo "30) Lynis(28 required)            31) Scan for virus"
                echo "32) Apps & services & auditing    33) Manual file check"
                echo "34) SysConf                       35) Firefox configuration (In testing)"
                echo "36) Add user to group             37) Remove user from group"
                echo "38) Lock users                    39) Permissions"
                echo "40) Kernel Upgrade                41) Boot Load(In testing)"
                echo "42) File move for configuring     43) linPEAS (In testing)"
                echo "44) Encryption (In testing)       45) Lock root"
                echo "46) See running programs (good for finding viruses)"
                echo "47) Read logs                     48) CIS (more in testing)"
                echo "49) STIG, very in testing         50) Fix apt (in testing)"
                echo "51) List All Config and Rule Files"
                echo "52) List all kernel modules       53) List running daemons"
                echo "54) "
	;;
	"Debian")
				echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
				echo "		 ██████╗ ███████╗██████╗  █████╗ ██╗███╗   ██╗			"
				echo "		 ██╔══██╗██╔════╝██╔══██╗██╔══██╗██║████╗  ██║			"
				echo "		 ██║  ██║█████╗  ██████╔╝███████║██║██╔██╗ ██║			"
				echo "		 ██║  ██║██╔══╝  ██╔══██╗██╔══██║██║██║╚██╗██║			"
				echo "		 ██████╔╝███████╗██████╔╝██║  ██║██║██║ ╚████║			"
				echo "	     ╚═════╝ ╚══════╝╚═════╝ ╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝			"
				echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
                echo " "
                echo "1) Update the machine.(Beginning) 2) Set automatic updates."
				echo "3) Search for prohibited file.	4) configure the firewall."
				echo "5) Configure login screen.		6) Create any new users."
				echo "7) Change all the passwords.		8) Delete any users."
				echo "9) Set all the admins.			10) List all cronjobs."
				echo "11) Set the password policy.		12) Set the lockout policy."
				echo "13) Remove the hacking tools.		14) Configure SSH."
				echo "15) Edit the sysctl.conf.			16) Export the sudoers file."
				echo "17) List all running processes.	18) Remove NetCat."
				echo "19) Reboot the machine.			20) Secure the root"
				echo "21) PostScript				    22) Disable ctrl-alt-del"
				echo "23) BASIC CIS               		(Used for quick pts)"
                echo "24) To do list(Other stuff)   	25) Run full (In dev)"
                echo "26) File search   	            27) Antivirus and defense"
                echo "28) Network/smb shares            29) UID change"
                echo "30) Lynis(28 required)            31) Scan for virus"
                echo "32) Apps & services & auditing    33) Manual file check"
                echo "34) SysConf                       35) Firefox configuration (In testing)"
                echo "36) Add user to group             37) Remove user from group"
                echo "38) Lock users                    39) Permissions"
                echo "40) Kernel Upgrade                41) Boot Load(In testing)"
                echo "42) File move for configuring     43) linPEAS (In testing)"
                echo "44) Encryption (In testing)       45) Lock root"
                echo "46) See running programs (good for finding viruses)"
                echo "47) Read logs                     48) CIS (more in testing)"
                echo "49) STIG, very in testing         50) Fix apt (in testing)"
                echo "51) List All Config and Rule Files"
                echo "52) Exit"
	;;
	esac

}
read_options(){
	case $opsys in
	"Ubuntu"|"Debian")
		local choice
		read -p "Please select item you wish to do: " choice

		case $choice in
			1) update;;
			2) autoUpdate;;
			3) pFiles;;
			4) configureFirewall;;
			5) loginConf;;
			6) createUser;;
			7) chgPasswd;;
			8) delUser;;
			9) admin;;
			10) cron;;
			11) passPol;;
			12) lockoutPol;;
			13) hakTools;;
			14) sshd;;
			15) sys;;
			16) sudoers;;
			17) proc;;
			18) nc;;
	 		19) reboot;;
			20) secRoot;;
			21) cat postScript; ;;
			22) CAD;;
            23) BASICCIS;;
            24) To-DoList;;
			25)runFull;;
            26) txtSearch;;
            27) RKProct;;
            28) ListShares;;
            29) chgUID;;
            30) lynisStuff;;
            31) sysSCAN;;
            32) AppsServicesAuditing;;
            33) ManualStuff;;
            34) SysConf;;
            35) firefoxConf;;
            36) AddToGroup;;
            37) RemoveFromGroup;;
            38) UserLock;;
            39) Permissions;;
            40) KernelUpgrade;;
            41) BootPerms;;
            42) FileMoveForConf;;
            43) linPEAS;;
            44) encryption;;
            45) DisableRoot;;
            46) compgen -c; ;;
            47) ReadLogs;;
            48) CISAuto;;
            49) STIGAuto;;
            50) AptFix;;
            51) ListConfFiles;;
            52) modules;;
            53) daemons;;
            54) exit 1;;
			*) echo "Sorry that is not an option please select another one..."
			;;
		esac
	;;
	esac
}

while true
do
	clear
	show_menu
	read_options
done
