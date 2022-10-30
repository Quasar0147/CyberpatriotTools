UserName=$(whoami)
LogTime=$(date '+%Y-%d %H:%M;%S')
DE=`echo $XDG_CURRENT_DESKTOP`

##Adds a pause statement
pause(){
	read -p "Press [Enter] key to continue..." fakeEnter
}

##Exits the script
exit20(){
	exit 1
	clear
}

##Detect the Operating System
gcc || apt-get install gcc >> /dev/null
gcc || yum install gcc >> /dev/null
gcc --version | grep -i ubuntu
if [ $? -eq 0 ]; then
	opsys="Ubuntu"
fi
gcc --version | grep -i debian >> /dev/null
if [ $? -eq 0 ]; then
	opsys="Debian"
fi

gcc --version | grep -i RedHat >> /dev/null
if [ $? -eq 0 ]; then
	opsys="RedHat"
fi

gcc --version | grep -i #CentOS >> /dev/null
if [ $? -eq 0 ]; then
	opsys="CentOS"
fi

##Updates the operating system, kernel, firefox, and libre office and also installs 'clamtk'
update(){

	case "$opsys" in
	"Debian"|"Ubuntu")
		sudo add-apt-repository -y ppa:libreoffice/ppa
		wait
		sudo apt-get update -y
		wait
		sudo apt-get upgrade -y
		wait
		sudo apt-get dist-upgrade -y
		wait
		killall firefox
		wait
		sudo apt-get --purge --reinstall install firefox -y
		wait
		sudo apt-get install clamtk -y
		wait

		pause
	;;
	"RedHat"|"CentOS")
		yum update -y
		wait
		yum upgrade -y
		wait
		yum update firefox -y
		wait
		yum install clamtk -y
		wait

		pause
	;;
	esac
}

##Creates copies of critical files
backup() {
	mkdir /BackUps
	##Backups the sudoers file
	sudo cp /etc/sudoers /Backups
	##Backups the home directory
	cp /etc/passwd /BackUps
	##Backups the log files
	cp -r /var/log /BackUps
	##Backups the passwd file
	cp /etc/passwd /BackUps
	##Backups the group file
	cp /etc/group /BackUps
	##Back ups the shadow file
	cp /etc/shadow /BackUps
	##Backing up the /var/spool/mail
	cp /var/spool/mail /Backups
	##backups all the home directories
	for x in `ls /home`
	do
		cp -r /home/$x /BackUps
	done

	pause
}

##Sets Automatic Updates on the machine.
autoUpdate() {
echo "$LogTime uss: [$UserName]# Setting auto updates." >> output.log
	case "$opsys" in
	"Debian"|"Ubuntu")

	##Set daily updates
		sed -i -e 's/APT::Periodic::Update-Package-Lists.*\+/APT::Periodic::Update-Package-Lists "1";/' /etc/apt/apt.conf.d/10periodic
		sed -i -e 's/APT::Periodic::Download-Upgradeable-Packages.*\+/APT::Periodic::Download-Upgradeable-Packages "0";/' /etc/apt/apt.conf.d/10periodic
##Sets default broswer
		sed -i 's/x-scheme-handler\/http=.*/x-scheme-handler\/http=firefox.desktop/g' /home/$UserName/.local/share/applications/mimeapps.list
##Set "install security updates"
		cat /etc/apt/sources.list | grep "deb http://security.ubuntu.com/ubuntu/ trusty-security universe main multiverse restricted"
		if [ $? -eq 1 ]
		then
			echo "deb http://security.ubuntu.com/ubuntu/ trusty-security universe main multiverse restricted" >> /etc/apt/sources.list
		fi

		echo "###Automatic updates###"
		cat /etc/apt/apt.conf.d/10periodic
		echo ""
		echo "###Important Security Updates###"
		cat /etc/apt/sources.list
		pause
	;;
	"RedHat"|"CentOS")

		yum -y install yum-cron
	;;
	esac
}

##Finds all prohibited files on the machine and deletes them
pFiles() {
echo "$LogTime uss: [$UserName]# Deleting media files..." >> output.log
	##Media files
	echo "###MEDIA FILES###" >> pFiles.log
    	find / -name "*.mov" -type f >> pFiles.log
    	find / -name "*.mp4" -type f >> pFiles.log
	find / -name "*.mp3" -type f >> pFiles.log
	find / -name "*.wav" -type f >> pFiles.log
	##Pictures
	echo "###PICTURES###" >> pFiles.log
#	find / -name "*.png" -type f >> pFiles.log
    find / -name "*.jpg" -type f >> pFiles.log
	find / -name "*.jpeg" -type f >> pFiles.log
#	find / -name "*.gif" -type f >> pFiles.log
	##Other Files
	echo "###OTHER###" >> pFiles.log
	find / -name "*.tar.gz" -type f >> pFiles.log
	find / -name "*.php" -type f >> pFiles.log
	find / -name "*backdoor*.*" -type f >> pFiles.log
	find / -name "*backdoor*.php" -type f >> pFiles.log
	##Items without groups
	echo "###FILES WITHOUT GROUPS###" >> pFiles.log
	find / -nogroup >> pFiles.log
	echo "###GAMES###" >> pFiles.log
	dpkg -l | grep -i game

	##Deletes audio files
	find / -name "*.mp3" -type f -delete
	##Deletes Video files
	find / -name "*.mov" -type f -delete
	find / -name "*.mp4" -type f -delete
#	find / -name "*.gif" -type f -delete
	##Deletes pictures
#	find / -name "*.png" -type f -delete
	find / -name "*.jpg" -type f -delete
	find / -name "*.jpeg" -type f -delete
echo "$LogTime uss: [$UserName]# Media files deleted." >> output.log
	cat pFiles.log
	pause
}

##Configures the firewall
configureFirewall() {
echo "$LogTime uss: [$UserName]# Checking for firewall..." >> output.log
	case "$opsys" in
	"Ubuntu"|"Debian")
		dpkg -l | grep ufw >> output.log
		if [ $? -eq 1 ]
		then
			apt-get install ufw >> output.log
		fi
echo "$LogTime uss: [$UserName]# Enabling firewall..." >> output.log
		sudo ufw enable >>output.log
		sudo ufw status >> output.log
		sleep 1
echo "$LogTime uss: [$UserName]# Firewall has been turned on and configured." >> output.log
		ufw status
		pause
	;;
	"RedHat"|"CentOS")
		yum install ufw
echo "$LogTime uss: [$UserName]# Enabling firewall..." >> output.log
                sudo ufw enable >>output.log
                sudo ufw status >> output.log
                sleep 1
echo "$LogTime uss: [$UserName]# Firewall has been turned on and configured." >> output.log
                ufw status
                pause
	;;
	esac
}

##Edits the /etc/gdm3 /etc/lightdm/lightdm.conf config files.
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
	;;
	"Ubuntu")
		typeset -r TMOUT=900
echo "$LogTime uss: [$UserName]# Creating /etc/lightdm/lightdm.conf for 12.04 compatability." >> output.log
		if [ -f /etc/lightdm/lightdm.conf ];
		then
			sed -i '$a allow-guest=false' /etc/lightdm/lightdm.conf
			sed -i '$a greeter-hide-users=true' /etc/lightdm/lightdm.conf
			sed -i '$a greeter-show-manual-login=true' /etc/lightdm/lightdm.conf

			##Finds automatic login user if there is one and takes it out
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
			pause
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
			pause
		fi
echo "$LogTime uss: [$UserName]# Editing the ../50-ubuntu.conf for ubuntu 14.04" >> output.log
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
echo "$LogTime uss: [$UserName]# Lightdm files have been configured" >> output.log

		cat /usr/share/lightdm/lightdm.conf.d/50-ubuntu.conf
		pause
		;;
	"RedHat"|"CentOS")
		typeset -r TMOUT=900
		mkdir /etc/dconf/db/gdm.d
		touch /etc/dconf/db/gdm.d/01-hide-users
		sed -i '$a [org/gnome/login-screen]' /etc/dconf/db/gdm.d/01-hide-users
		sed -i '$a banner-message-enable=true'/etc/dconf/db/gdm.d/01-hide-users
		sed -i '$a banner-message-text="This is a restricted server xd."' /etc/dconf/db/gdm.d/01-hide-users
		sed -i '$a disable-restart-buttons=true' /etc/dconf/db/gdm.d/01-hide-users
		sed -i '$a disable-user-list=true' /etc/dconf/db/gdm.d/01-hide-users

		touch /etc/dconf/profile/gdm
		sed -i '$a user-db:user' /etc/dconf/profile/gdm
		sed -i '$a system-db:gdm' /etc/dconf/profile/gdm
		dconf update
		;;
	esac
}

##Creates any missing users
createUser() {
	read -p "Are there any users you would like to add?[y/n]: " a
	while [ $a = y ]
	do
		read -p "Please enter the name of the user: " user
		useradd $user
		mkdir /home/$user
		read -p "Are there any more users you would like to add?[y/n]: " a
	done

	pause
}

##Changes all the user passwords
chgPasswd(){
echo "$LogTime uss: [$UserName]# Changing all the user passwords to Cyb3rPatr!0t$." >> output.log
	##Look for valid users that have different UID that not 1000+
	cut -d: -f1,3 /etc/passwd | egrep ':[0-9]{4}$' | cut -d: -f1 > users
	##Looks for users with the UID and GID of 0
	hUSER=`cut -d: -f1,3 /etc/passwd | egrep ':[0]{1}$' | cut -d: -f1`
	echo "$hUSER is a hidden user"
	sed -i '/root/ d' users

	read "What is the password: " PASS
    read "Do policies: " Pol
	for x in `cat users`
	do
		echo -e "$PASS\n$PASS" | passwd $x >> output.log
		echo -e "Password for $x has been changed."
        if [ pol = y ];
        then
            chage -M 90 -m 7 -W 15 $x
        fi
	done
echo "$LogTime uss: [$UserName]# Passwords have been changed." >> output.log

	pause
}

##Sets the password policy
passPol() {
echo "$LogTime uss: [$UserName]# Setting password policy..." >> output.log
echo "$LogTime uss: [$UserName]# Installing Craklib..." >> output.log
	apt-get install libpam-cracklib || yum install libpam-cracklib
	wait
echo "$LogTime uss: [$UserName]# Cracklib installed." >> output.log
	sed -i.bak -e 's/PASS_MAX_DAYS\t[[:digit:]]\+/PASS_MAX_DAYS\t90/' /etc/login.defs
	sed -i -e 's/PASS_MIN_DAYS\t[[:digit:]]\+/PASS_MIN_DAYS\t10/' /etc/login.defs
	sed -i -e 's/PASS_WARN_AGE\t[[:digit:]]\+/PASS_WARN_AGE\t7/' /etc/login.defs
	sed -i -e 's/difok=3\+/difok=3 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1/' /etc/pam.d/common-password
echo "$LogTime uss: [$UserName]# Password Policy." >> output.log

	pause
}

##Deletes users
delUser() {
	for x in `cat users`
	do
		read -p "Is $x a valid user?[y/n]: " a
		if [ $a = n ];
		then
			mv /home/$x /home/dis_$x
			sed -i -e "/$x/ s/^#*/#/" /etc/passwd
			sleep 1
		fi
	done
	pause
}

##Asks for any admin users
admin() {
	for x in `cat users`
	do
		read -p "Is $x considered an admin?[y/n]: " a
		if [ $a = y ]
		then
			##Adds to the adm group
			sudo usermod -a -G adm $x

			##Adds to the sudo group
			sudo usermod -a -G sudo $x
		else
			##Removes from the adm group
			sudo deluser $x adm

			##Removes from the sudo group
			sudo deluser $x sudo
		fi
	done

	pause
}

##Secures the root account
secRoot(){
echo "$LogTime uss: [$UserName] # Securing root..." >> output.log
	PASS='Cyb3rPatr!0t$'
	echo -e "$PASS\n$PASS" | passwd root  >> output.log
	sudo passwd -l root
echo "$LogTime uss: [$UserName] # Root has been secured." >> output.log
}

##Sets the lockout policy
lockoutPol() {
echo "$LogTime uss: [$UserName]# Setting lockout policy..." >> output.log
	sed -i 's/auth\trequisite\t\t\tpam_deny.so\+/auth\trequired\t\t\tpam_deny.so/' /etc/pam.d/common-auth
	sed -i '$a auth\trequired\t\t\tpam_tally2.so deny=5 unlock_time=1800 onerr=fail' /etc/pam.d/common-auth
	sed -i 's/sha512\+/sha512 remember=13/' /etc/pam.d/common-password
echo "$LogTime uss: [$UserName]# Lockout poicy set." >> output.log

	pause
}

##Checks for SSH, if it is needed then it is installed and secured
##FiX FOR FEDORA
sshd() {
echo "$LogTime uss: [$UserName]# Checking for ssh..." >> output.log
	dpkg -l | grep openssh-server >> output.log
        	if [ $? -eq 0 ];
        	then
                	read -p "Do you want SSH installed on the system?[y/n]: " a
                	if [ $a = n ];
                	then
                        	apt-get autoremove -y --purge openssh-server ssh >> output.log
echo "$LogTime uss: [$UserName]# SSH has been removed." >> output.log
	         		else
echo "$LogTime uss: [$UserName]# SSH has been found, securing now..." >> output.log
							sed -i 's/LoginGraceTime .*/LoginGraceTime 60/g' /etc/ssh/sshd_config
                        	sed -i 's/PermitRootLogin .*/PermitRootLogin no/g' /etc/ssh/sshd_config
                        	sed -i 's/Protocol .*/Protocol 2/g' /etc/ssh/sshd_config
                        	sed -i 's/#PermitEmptyPasswords .*/PermitEmptyPasswords no/g' /etc/ssh/sshd_config
                        	sed -i 's/PasswordAuthentication .*/PasswordAuthentication yes/g' /etc/ssh/sshd_config
                        	sed -i 's/X11Forwarding .*/X11Forwarding no/g' /etc/ssh/sshd_config

							##Only allows authroized users
							sed -i '$a AllowUsers' /etc/ssh/sshd_config
							for x in `cat users`
							do
								sed -i "/^AllowUser/ s/$/ $x /" /etc/ssh/sshd_config
							done
echo "$LogTime uss: [$UserName]# SSH has been secured." >> output.log
				pause
                	fi
        	else
                	read -p "Does SSH NEED to be installed?[y/n]: " a
                	if [ $a = y ];
                	then
echo "$LogTime uss: [$UserName]# Installing and securing SSH now..." >> output.log
                        	apt-get install -y openssh-server ssh >> output.log
				wait
							sed -i 's/LoginGraceTime .*/LoginGraceTime 60/g' /etc/ssh/sshd_config
                        	sed -i 's/PermitRootLogin .*/PermitRootLogin no/g' /etc/ssh/sshd_config
                        	sed -i 's/Protocol .*/Protocol 2/g' /etc/ssh/sshd_config
                        	sed -i 's/#PermitEmptyPasswords .*/PermitEmptyPasswords no/g' /etc/ssh/sshd_config
                        	sed -i 's/PasswordAuthentication .*/PasswordAuthentication yes/g' /etc/ssh/sshd_config
                        	sed -i 's/X11Forwarding .*/X11Forwarding no/g' /etc/ssh/sshd_config
							##uses PAM
							##Uses Privilege seperation

							##Only allows authroized users
							sed -i '$a AllowUsers' /etc/ssh/sshd_config
							for x in `cat users`
							do
								sed -i "/^AllowUser/ s/$/ $x /" /etc/ssh/sshd_config
							done
				pause
			fi
        	fi
}

##Secures the /etc/shadow file
secureShadow() {
echo "$LogTime uss: [$UserName]# Securing /etc/shadow..." >> output.log
	chmod 640 /etc/shadow

	ls -l /etc/shadow
	pause
}

##Removes basik hak tools
hakTools() {

##CHANGE TO GREP -i
echo "$LogTime uss: [$UserName]# Removing hacking tools..." >> output.log
##Looks for apache web server
	dpkg -l | grep apache >> output.log
	if [ $? -eq 0 ];
	then
        	read -p "Do you want apache installed on the system[y/n]: "
        	if [ $a = n ];
        	then
      	        	apt-get autoremove -y --purge apache2 >> output.log
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
				else
					##Installs and configures apache
					apt-get install apache2 -y
						chown -R root:root /etc/apache2
						chown -R root:root /etc/apache
						echo \<Directory \> >> /etc/apache2/apache2.conf
						echo -e ' \t AllowOverride None' >> /etc/apache2/apache2.conf
						echo -e ' \t Order Deny,Allow' >> /etc/apache2/apache2.conf
						echo -e ' \t Deny from all' >> /etc/apache2/apache2.conf
						echo UserDir disabled root >> /etc/apache2/apache2.conf

					##Installs and configures sql
					apt-get install mysql-server -y

					##Installs and configures php5
					apt-get install php5 -y
					chmod 640 /etc/php5/apache2/php.ini
				fi
        	fi
	else
        echo "Apache is not installed"
		sleep 1
	fi
##Looks for john the ripper
	dpkg -l | grep john >> output.log
	if [ $? -eq 0 ];
	then
        	echo "JOHN HAS BEEEN FOUND! DIE DIE DIE"
        	apt-get autoremove -y --purge john >> output.log
        	echo "John has been ripped"
			sleep 1
	else
        	echo "John The Ripper has not been found on the system"
			sleep 1
	fi
##Look for HYDRA
	dpkg -l | grep hydra >>output.log
	if [ $? -eq 0 ];
	then
		echo "HEIL HYDRA"
		apt-get autoremove -y --purge hydra >> output.log
	else
		echo "Hydra has not been found."
	fi
##Looks for nginx web server
	dpkg -l | grep nginx >> output.log
	if [ $? -eq 0 ];
	then
        	echo "NGINX HAS BEEN FOUND! OHHHH NOOOOOO!"
        	apt-get autoremove -y --purge nginx >> output.log
	else
        	echo "NGINX has not been found"
			sleep 1
	fi
##Looks for samba
	if [ -d /etc/samba ];
	then
		read -p "Samba has been found on this system, do you want to remove it?[y/n]: " a
		if [ $a = y ];
		then
echo "$LogTime uss: [$UserName]# Uninstalling samba..." >> output.log
			sudo apt-get autoremove --purge -y samba >> output.log
			sudo apt-get autoremove --purge -y samba >> output.log
echo "$LogTime uss: [$UserName]# Samba has been removed." >> output.log
		else
			sed -i '82 i\restrict anonymous = 2' /etc/samba/smb.conf
			##List shares
		fi
	else
		echo "Samba has not been found."
		sleep 1
	fi
##LOOK FOR DNS
	if [ -d /etc/bind ];
	then
		read -p "DNS server is running would you like to shut it down?[y/n]: " a
		if [ $a = y ];
		then
			apt-get autoremove -y --purge bind9
		fi
	else
		echo "DNS not found."
		sleep 1
	fi
##Looks for FTP
	dpkg -l | grep -i 'vsftpd|ftp' >> output.log
	if [ $? -eq 0 ]
	then
		read -p "FTP Server has been installed, would you like to remove it?[y/n]: " a
		if [ $a = y ]
		then
			PID = `pgrep vsftpd`
			sed -i 's/^/#/' /etc/vsftpd.conf
			kill $PID
			apt-get autoremove -y --purge vsftpd ftp
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
##Looks for TFTPD
	dpkg -l | grep tftpd >> output.log
	if [ $? -eq 0 ]
	then
		read -p "TFTPD has been installed, would you like to remove it?[y/n]: " a
		if [ $a = y ]
		then
			apt-get autoremove -y --purge tftpd
		fi
	else
		echo "TFTPD not found."
		sleep 1
	fi
##Looking for VNC
	dpkg -l | grep -E 'x11vnc|tightvncserver' >> output.log
	if [ $? -eq 0 ]
	then
		read -p "VNC has been installed, would you like to remove it?[y/n]: " a
		if [ $a = y ]
		then
			apt-get autoremove -y --purge x11vnc tightvncserver
		##else
			##Configure VNC
		fi
	else
		echo "VNC not found."
		sleep 1
	fi

##Looking for NFS
	dpkg -l | grep nfs-kernel-server >> output.log
	if [ $? -eq 0 ]
	then
		read -p "NFS has been found, would you like to remove it?[y/n]: " a
		if [ $a = 0 ]
		then
			apt-get autoremove -y --purge nfs-kernel-server
		##else
			##Configure NFS
		fi
	else
		echo "NFS has not been found."
		sleep 1
	fi
##Looks for snmp
	dpkg -l | grep snmp >> output.log
	if [ $? -eq 0 ]
	then
		echo "SNMP HAS BEEN LOCATED!"
		apt-get autoremove -y --purge snmp
	else
		echo "SNMP has not been found."
		sleep 1
	fi
##Looks for sendmail and postfix
	dpkg -l | grep -E 'postfix|sendmail' >> output.log
	if [ $? -eq 0 ]
	then
		echo "Mail servers have been found."
		apt-get autoremove -y --purge postfix sendmail
	else
		echo "Mail servers have not been located."
		sleep 1
	fi
##Looks xinetd
	dpkg -l | grep xinetd >> output.log
	if [ $? -eq 0 ]
	then
		echo "XINIT HAS BEEN FOUND!"
		apt-get autoremove -y --purge xinetd
	else
		echo "XINETD has not been found."
		sleep 1
	fi
    sytemctl unmask ssh
    sytemctl enable ssh
    sytemctl start ssh
    echo "SSH activated"
    sytemctl unmask proftp
    sytemctl enable proftp
    sytemctl start proftp
    echo "proftp activated"
	pause
}
Beirman(){
    echo "Created by Matthew Bierman, Lightning McQueens, Faith Lutheran Middle & High School, Las Vegas, NV, USA"
    echo "Last Modified on Friday, January 21st, 2016, 7:20am"
    echo "Linux Ubuntu Script"
    startTime=$(date +"%s")
    printTime()
    {
    endTime=$(date +"%s")
    diffTime=$(($endTime-$startTime))
    if [ $(($diffTime / 60)) -lt 10 ]
    then
    	if [ $(($diffTime % 60)) -lt 10 ]
    	then
    		echo -e "0$(($diffTime / 60)):0$(($diffTime % 60)) -- $1" >> ~/Desktop/Script.log
    	else
    		echo -e "0$(($diffTime / 60)):$(($diffTime % 60)) -- $1" >> ~/Desktop/Script.log
    	fi
    else
    	if [ $(($diffTime % 60)) -lt 10 ]
    	then
    		echo -e "$(($diffTime / 60)):0$(($diffTime % 60)) -- $1" >> ~/Desktop/Script.log
    	else
    		echo -e "$(($diffTime / 60)):$(($diffTime % 60)) -- $1" >> ~/Desktop/Script.log
    	fi
    fi
    }

    touch ~/Desktop/Script.log
    echo > ~/Desktop/Script.log
    chmod 777 ~/Desktop/Script.log

    if [[ $EUID -ne 0 ]]
    then
    echo This script must be run as root
    exit
    fi
    printTime "Script is being run as root."

    printTime "The current OS is Linux Ubuntu."

    mkdir -p ~/Desktop/backups
    chmod 777 ~/Desktop/backups
    printTime "Backups folder created on the Desktop."

    cp /etc/group ~/Desktop/backups/
    cp /etc/passwd ~/Desktop/backups/

    printTime "/etc/group and /etc/passwd files backed up."

    echo Type all user account names, with a space in between
    read -a users

    usersLength=${#users[@]}

    for (( i=0;i<$usersLength;i++))
    do
    clear
    echo ${users[${i}]}
    echo Delete ${users[${i}]}? yes or no
    read yn1
    if [ $yn1 == yes ]
    then
    	userdel -r ${users[${i}]}
    	printTime "${users[${i}]} has been deleted."
    else
    	echo Make ${users[${i}]} administrator? yes or no
    	read yn2
    	if [ $yn2 == yes ]
    	then
    		gpasswd -a ${users[${i}]} sudo
    		gpasswd -a ${users[${i}]} adm
    		gpasswd -a ${users[${i}]} lpadmin
    		gpasswd -a ${users[${i}]} sambashare
    		printTime "${users[${i}]} has been made an administrator."
    	else
    		gpasswd -d ${users[${i}]} sudo
    		gpasswd -d ${users[${i}]} adm
    		gpasswd -d ${users[${i}]} lpadmin
    		gpasswd -d ${users[${i}]} sambashare
    		gpasswd -d ${users[${i}]} root
    		printTime "${users[${i}]} has been made a standard user."
    	fi

    	echo Make custom password for ${users[${i}]}? yes or no
    	read yn3
    	if [ $yn3 == yes ]
    	then
    		echo Password:
    		read pw
    		echo -e "$pw\n$pw" | passwd ${users[${i}]}
    		printTime "${users[${i}]} has been given the password '$pw'."
    	else
    		echo -e "Moodle!22\nMoodle!22" | passwd ${users[${i}]}
    		printTime "${users[${i}]} has been given the password 'Moodle!22'."
    	fi
    	passwd -x30 -n3 -w7 ${users[${i}]}
    	usermod -L ${users[${i}]}
    	printTime "${users[${i}]}'s password has been given a maximum age of 30 days, minimum of 3 days, and warning of 7 days. ${users[${i}]}'s account has been locked."
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
    printTime "A user account for ${usersNew[${i}]} has been created."
    clear
    echo Make ${usersNew[${i}]} administrator? yes or no
    read ynNew
    if [ $ynNew == yes ]
    then
    	gpasswd -a ${usersNew[${i}]} sudo
    	gpasswd -a ${usersNew[${i}]} adm
    	gpasswd -a ${usersNew[${i}]} lpadmin
    	gpasswd -a ${usersNew[${i}]} sambashare
    	printTime "${usersNew[${i}]} has been made an administrator."
    else
    	printTime "${usersNew[${i}]} has been made a standard user."
    fi

    passwd -x30 -n3 -w7 ${usersNew[${i}]}
    usermod -L ${usersNew[${i}]}
    printTime "${usersNew[${i}]}'s password has been given a maximum age of 30 days, minimum of 3 days, and warning of 7 days. ${users[${i}]}'s account has been locked."
    done

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

    clear
    unalias -a
    printTime "All alias have been removed."

    clear
    usermod -L root
    printTime "Root account has been locked. Use 'usermod -U root' to unlock it."

    clear
    chmod 640 .bash_history
    printTime "Bash history file permissions set."

    clear
    chmod 604 /etc/shadow
    printTime "Read/Write permissions on shadow have been set."

    clear
    printTime "Check for any user folders that do not belong to any users in /home/."
    ls -a /home/ >> ~/Desktop/Script.log

    clear
    printTime "Check for any files for users that should not be administrators in /etc/sudoers.d."
    ls -a /etc/sudoers.d >> ~/Desktop/Script.log

    clear
    cp /etc/rc.local ~/Desktop/backups/
    echo > /etc/rc.local
    echo 'exit 0' >> /etc/rc.local
    printTime "Any startup scripts have been removed."

    clear
    apt-get install ufw -y -qq
    ufw enable
    ufw deny 1337
    printTime "Firewall enabled and port 1337 blocked."

    clear
    env i='() { :;}; echo Your system is Bash vulnerable' bash -c "echo Bash vulnerability test"
    printTime "Shellshock Bash vulnerability has been fixed."

    clear
    chmod 777 /etc/hosts
    cp /etc/hosts ~/Desktop/backups/
    echo > /etc/hosts
    echo -e "127.0.0.1 localhost\n127.0.1.1 $USER\n::1 ip6-localhost ip6-loopback\nfe00::0 ip6-localnet\nff00::0 ip6-mcastprefix\nff02::1 ip6-allnodes\nff02::2 ip6-allrouters" >> /etc/hosts
    chmod 644 /etc/hosts
    printTime "HOSTS file has been set to defaults."

    clear
    chmod 777 /etc/lightdm/lightdm.conf
    cp /etc/lightdm/lightdm.conf ~/Desktop/backups/
    echo > /etc/lightdm/lightdm.conf
    echo -e '[SeatDefaults]\nallow-guest=false\ngreeter-hide-users=true\ngreeter-show-manual-login=true' >> /etc/lightdm/lightdm.conf
    chmod 644 /etc/lightdm/lightdm.conf
    printTime "LightDM has been secured."

    clear
    find /bin/ -name "*.sh" -type f -delete
    printTime "Scripts in bin have been removed."

    clear
    cp /etc/default/irqbalance ~/Desktop/backups/
    echo > /etc/default/irqbalance
    echo -e "#Configuration for the irqbalance daemon\n\n#Should irqbalance be enabled?\nENABLED=\"0\"\n#Balance the IRQs only once?\nONESHOT=\"0\"" >> /etc/default/irqbalance
    printTime "IRQ Balance has been disabled."

    clear
    cp /etc/sysctl.conf ~/Desktop/backups/
    echo > /etc/sysctl.conf
    echo -e "# Controls IP packet forwarding\nnet.ipv4.ip_forward = 0\n\n# IP Spoofing protection\nnet.ipv4.conf.all.rp_filter = 1\nnet.ipv4.conf.default.rp_filter = 1\n\n# Ignore ICMP broadcast requests\nnet.ipv4.icmp_echo_ignore_broadcasts = 1\n\n# Disable source packet routing\nnet.ipv4.conf.all.accept_source_route = 0\nnet.ipv6.conf.all.accept_source_route = 0\nnet.ipv4.conf.default.accept_source_route = 0\nnet.ipv6.conf.default.accept_source_route = 0\n\n# Ignore send redirects\nnet.ipv4.conf.all.send_redirects = 0\nnet.ipv4.conf.default.send_redirects = 0\n\n# Block SYN attacks\nnet.ipv4.tcp_syncookies = 1\nnet.ipv4.tcp_max_syn_backlog = 2048\nnet.ipv4.tcp_synack_retries = 2\nnet.ipv4.tcp_syn_retries = 5\n\n# Log Martians\nnet.ipv4.conf.all.log_martians = 1\nnet.ipv4.icmp_ignore_bogus_error_responses = 1\n\n# Ignore ICMP redirects\nnet.ipv4.conf.all.accept_redirects = 0\nnet.ipv6.conf.all.accept_redirects = 0\nnet.ipv4.conf.default.accept_redirects = 0\nnet.ipv6.conf.default.accept_redirects = 0\n\n# Ignore Directed pings\nnet.ipv4.icmp_echo_ignore_all = 1\n\n# Accept Redirects? No, this is not router\nnet.ipv4.conf.all.secure_redirects = 0\n\n# Log packets with impossible addresses to kernel log? yes\nnet.ipv4.conf.default.secure_redirects = 0\n\n########## IPv6 networking start ##############\n# Number of Router Solicitations to send until assuming no routers are present.\n# This is host and not router\nnet.ipv6.conf.default.router_solicitations = 0\n\n# Accept Router Preference in RA?\nnet.ipv6.conf.default.accept_ra_rtr_pref = 0\n\n# Learn Prefix Information in Router Advertisement\nnet.ipv6.conf.default.accept_ra_pinfo = 0\n\n# Setting controls whether the system will accept Hop Limit settings from a router advertisement\nnet.ipv6.conf.default.accept_ra_defrtr = 0\n\n#router advertisements can cause the system to assign a global unicast address to an interface\nnet.ipv6.conf.default.autoconf = 0\n\n#how many neighbor solicitations to send out per address?\nnet.ipv6.conf.default.dad_transmits = 0\n\n# How many global unicast IPv6 addresses can be assigned to each interface?
    net.ipv6.conf.default.max_addresses = 1\n\n########## IPv6 networking ends ##############" >> /etc/sysctl.conf
    sysctl -p >> /dev/null
    printTime "Sysctl has been configured."


    echo Disable IPv6?
    read ipv6YN
    if [ $ipv6YN == yes ]
    then
    echo -e "\n\n# Disable IPv6\nnet.ipv6.conf.all.disable_ipv6 = 1\nnet.ipv6.conf.default.disable_ipv6 = 1\nnet.ipv6.conf.lo.disable_ipv6 = 1" >> /etc/sysctl.conf
    sysctl -p >> /dev/null
    printTime "IPv6 has been disabled."
    fi

    clear
    if [ $sambaYN == no ]
    then
    ufw deny netbios-ns
    ufw deny netbios-dgm
    ufw deny netbios-ssn
    ufw deny microsoft-ds
    apt-get purge samba -y -qq
    apt-get purge samba-common -y  -qq
    apt-get purge samba-common-bin -y -qq
    apt-get purge samba4 -y -qq
    clear
    printTime "netbios-ns, netbios-dgm, netbios-ssn, and microsoft-ds ports have been denied. Samba has been removed."
    elif [ $sambaYN == yes ]
    then
    ufw allow netbios-ns
    ufw allow netbios-dgm
    ufw allow netbios-ssn
    ufw allow microsoft-ds
    apt-get install samba -y -qq
    apt-get install system-config-samba -y -qq
    cp /etc/samba/smb.conf ~/Desktop/backups/
    if [ "$(grep '####### Authentication #######' /etc/samba/smb.conf)"==0 ]
    then
    	sed -i 's/####### Authentication #######/####### Authentication #######\nsecurity = user/g' /etc/samba/smb.conf
    fi
    sed -i 's/usershare allow guests = no/usershare allow guests = yes/g' /etc/samba/smb.conf

    echo Type all user account names, with a space in between
    read -a usersSMB
    usersSMBLength=${#usersSMB[@]}
    for (( i=0;i<$usersSMBLength;i++))
    do
    	echo -e 'Moodle!22\nMoodle!22' | smbpasswd -a ${usersSMB[${i}]}
    	printTime "${usersSMB[${i}]} has been given the password 'Moodle!22' for Samba."
    done
    printTime "netbios-ns, netbios-dgm, netbios-ssn, and microsoft-ds ports have been denied. Samba config file has been configured."
    clear
    else
    echo Response not recognized.
    fi
    printTime "Samba is complete."

    clear
    if [ $ftpYN == no ]
    then
    ufw deny ftp
    ufw deny sftp
    ufw deny saft
    ufw deny ftps-data
    ufw deny ftps
    apt-get purge vsftpd -y -qq
    printTime "vsFTPd has been removed. ftp, sftp, saft, ftps-data, and ftps ports have been denied on the firewall."
    elif [ $ftpYN == yes ]
    then
    ufw allow ftp
    ufw allow sftp
    ufw allow saft
    ufw allow ftps-data
    ufw allow ftps
    cp /etc/vsftpd/vsftpd.conf ~/Desktop/backups/
    cp /etc/vsftpd.conf ~/Desktop/backups/
    gedit /etc/vsftpd/vsftpd.conf&gedit /etc/vsftpd.conf
    service vsftpd restart
    printTime "ftp, sftp, saft, ftps-data, and ftps ports have been allowed on the firewall. vsFTPd service has been restarted."
    else
    echo Response not recognized.
    fi
    printTime "FTP is complete."


    clear
    if [ $sshYN == no ]
    then
    ufw deny ssh
    apt-get purge openssh-server -y -qq
    printTime "SSH port has been denied on the firewall. Open-SSH has been removed."
    elif [ $sshYN == yes ]
    then
    apt-get install openssh-server -y -qq
    ufw allow ssh
    cp /etc/ssh/sshd_config ~/Desktop/backups/
    echo Type all user account names, with a space in between
    read usersSSH
    echo -e "# Package generated configuration file\n# See the sshd_config(5) manpage for details\n\n# What ports, IPs and protocols we listen for\nPort 2200\n# Use these options to restrict which interfaces/protocols sshd will bind to\n#ListenAddress ::\n#ListenAddress 0.0.0.0\nProtocol 2\n# HostKeys for protocol version \nHostKey /etc/ssh/ssh_host_rsa_key\nHostKey /etc/ssh/ssh_host_dsa_key\nHostKey /etc/ssh/ssh_host_ecdsa_key\nHostKey /etc/ssh/ssh_host_ed25519_key\n#Privilege Separation is turned on for security\nUsePrivilegeSeparation yes\n\n# Lifetime and size of ephemeral version 1 server key\nKeyRegenerationInterval 3600\nServerKeyBits 1024\n\n# Logging\nSyslogFacility AUTH\nLogLevel VERBOSE\n\n# Authentication:\nLoginGraceTime 60\nPermitRootLogin no\nStrictModes yes\n\nRSAAuthentication yes\nPubkeyAuthentication yes\n#AuthorizedKeysFile	%h/.ssh/authorized_keys\n\n# Don't read the user's ~/.rhosts and ~/.shosts files\nIgnoreRhosts yes\n# For this to work you will also need host keys in /etc/ssh_known_hosts\nRhostsRSAAuthentication no\n# similar for protocol version 2\nHostbasedAuthentication no\n# Uncomment if you don't trust ~/.ssh/known_hosts for RhostsRSAAuthentication\n#IgnoreUserKnownHosts yes\n\n# To enable empty passwords, change to yes (NOT RECOMMENDED)\nPermitEmptyPasswords no\n\n# Change to yes to enable challenge-response passwords (beware issues with\n# some PAM modules and threads)\nChallengeResponseAuthentication yes\n\n# Change to no to disable tunnelled clear text passwords\nPasswordAuthentication no\n\n# Kerberos options\n#KerberosAuthentication no\n#KerberosGetAFSToken no\n#KerberosOrLocalPasswd yes\n#KerberosTicketCleanup yes\n\n# GSSAPI options\n#GSSAPIAuthentication no\n#GSSAPICleanupCredentials yes\n\nX11Forwarding no\nX11DisplayOffset 10\nPrintMotd no\nPrintLastLog no\nTCPKeepAlive yes\n#UseLogin no\n\nMaxStartups 2\n#Banner /etc/issue.net\n\n# Allow client to pass locale environment variables\nAcceptEnv LANG LC_*\n\nSubsystem sftp /usr/lib/openssh/sftp-server\n\n# Set this to 'yes' to enable PAM authentication, account processing,\n# and session processing. If this is enabled, PAM authentication will\n# be allowed through the ChallengeResponseAuthentication and\n# PasswordAuthentication.  Depending on your PAM configuration,\n# PAM authentication via ChallengeResponseAuthentication may bypass\n# the setting of \"PermitRootLogin without-password\".\n# If you just want the PAM account and session checks to run without\n# PAM authentication, then enable this but set PasswordAuthentication\n# and ChallengeResponseAuthentication to 'no'.\nUsePAM yes\n\nAllowUsers $usersSSH\nDenyUsers\nRhostsAuthentication no\nClientAliveInterval 300\nClientAliveCountMax 0\nVerifyReverseMapping yes\nAllowTcpForwarding no\nUseDNS no\nPermitUserEnvironment no" > /etc/ssh/sshd_config
    service ssh restart
    mkdir ~/.ssh
    chmod 700 ~/.ssh
    ssh-keygen -t rsa
    printTime "SSH port has been allowed on the firewall. SSH config file has been configured. SSH RSA 2048 keys have been created."
    else
    echo Response not recognized.
    fi
    printTime "SSH is complete."

    clear
    if [ $telnetYN == no ]
    then
    ufw deny telnet
    ufw deny rtelnet
    ufw deny telnets
    apt-get purge telnet -y -qq
    apt-get purge telnetd -y -qq
    apt-get purge inetutils-telnetd -y -qq
    apt-get purge telnetd-ssl -y -qq
    printTime "Telnet port has been denied on the firewall and Telnet has been removed."
    elif [ $telnetYN == yes ]
    then
    ufw allow telnet
    ufw allow rtelnet
    ufw allow telnets
    printTime "Telnet port has been allowed on the firewall."
    else
    echo Response not recognized.
    fi
    printTime "Telnet is complete."



    clear
    if [ $mailYN == no ]
    then
    ufw deny smtp
    ufw deny pop2
    ufw deny pop3
    ufw deny imap2
    ufw deny imaps
    ufw deny pop3s
    printTime "smtp, pop2, pop3, imap2, imaps, and pop3s ports have been denied on the firewall."
    elif [ $mailYN == yes ]
    then
    ufw allow smtp
    ufw allow pop2
    ufw allow pop3
    ufw allow imap2
    ufw allow imaps
    ufw allow pop3s
    printTime "smtp, pop2, pop3, imap2, imaps, and pop3s ports have been allowed on the firewall."
    else
    echo Response not recognized.
    fi
    printTime "Mail is complete."



    clear
    if [ $printYN == no ]
    then
    ufw deny ipp
    ufw deny printer
    ufw deny cups
    printTime "ipp, printer, and cups ports have been denied on the firewall."
    elif [ $printYN == yes ]
    then
    ufw allow ipp
    ufw allow printer
    ufw allow cups
    printTime "ipp, printer, and cups ports have been allowed on the firewall."
    else
    echo Response not recognized.
    fi
    printTime "Printing is complete."



    clear
    if [ $dbYN == no ]
    then
    ufw deny ms-sql-s
    ufw deny ms-sql-m
    ufw deny mysql
    ufw deny mysql-proxy
    apt-get purge mysql -y -qq
    apt-get purge mysql-client-core-5.5 -y -qq
    apt-get purge mysql-client-core-5.6 -y -qq
    apt-get purge mysql-common-5.5 -y -qq
    apt-get purge mysql-common-5.6 -y -qq
    apt-get purge mysql-server -y -qq
    apt-get purge mysql-server-5.5 -y -qq
    apt-get purge mysql-server-5.6 -y -qq
    apt-get purge mysql-client-5.5 -y -qq
    apt-get purge mysql-client-5.6 -y -qq
    apt-get purge mysql-server-core-5.6 -y -qq
    printTime "ms-sql-s, ms-sql-m, mysql, and mysql-proxy ports have been denied on the firewall. MySQL has been removed."
    elif [ $dbYN == yes ]
    then
    ufw allow ms-sql-s
    ufw allow ms-sql-m
    ufw allow mysql
    ufw allow mysql-proxy
    apt-get install mysql-server-5.6 -y -qq
    cp /etc/my.cnf ~/Desktop/backups/
    cp /etc/mysql/my.cnf ~/Desktop/backups/
    cp /usr/etc/my.cnf ~/Desktop/backups/
    cp ~/.my.cnf ~/Desktop/backups/
    if grep -q "bind-address" "/etc/mysql/my.cnf"
    then
    	sed -i "s/bind-address\t\t=.*/bind-address\t\t= 127.0.0.1/g" /etc/mysql/my.cnf
    fi
    gedit /etc/my.cnf&gedit /etc/mysql/my.cnf&gedit /usr/etc/my.cnf&gedit ~/.my.cnf
    service mysql restart
    printTime "ms-sql-s, ms-sql-m, mysql, and mysql-proxy ports have been allowed on the firewall. MySQL has been installed. MySQL config file has been secured. MySQL service has been restarted."
    else
    echo Response not recognized.
    fi
    printTime "MySQL is complete."



    clear
    if [ $httpYN == no ]
    then
    ufw deny http
    ufw deny https
    apt-get purge apache2 -y -qq
    rm -r /var/www/*
    printTime "http and https ports have been denied on the firewall. Apache2 has been removed. Web server files have been removed."
    elif [ $httpYN == yes ]
    then
    apt-get install apache2 -y -qq
    ufw allow http
    ufw allow https
    cp /etc/apache2/apache2.conf ~/Desktop/backups/
    if [ -e /etc/apache2/apache2.conf ]
    then
    	  echo -e '\<Directory \>\n\t AllowOverride None\n\t Order Deny,Allow\n\t Deny from all\n\<Directory \/\>\nUserDir disabled root' >> /etc/apache2/apache2.conf
    fi
    chown -R root:root /etc/apache2

    printTime "http and https ports have been allowed on the firewall. Apache2 config file has been configured. Only root can now access the Apache2 folder."
    else
    echo Response not recognized.
    fi
    printTime "Web Server is complete."



    clear
    if [ $dnsYN == no ]
    then
    ufw deny domain
    apt-get purge bind9 -qq
    printTime "domain port has been denied on the firewall. DNS name binding has been removed."
    elif [ $dnsYN == yes ]
    then
    ufw allow domain
    printTime "domain port has been allowed on the firewall."
    else
    echo Response not recognized.
    fi
    printTime "DNS is complete."


    clear
    if [ $mediaFilesYN == no ]
    then
    find / -name "*.midi" -type f >> ~/Desktop/Script.log
    find / -name "*.mid" -type f >> ~/Desktop/Script.log
    find / -name "*.mod" -type f >> ~/Desktop/Script.log
    find / -name "*.mp3" -type f >> ~/Desktop/Script.log
    find / -name "*.mp2" -type f >> ~/Desktop/Script.log
    find / -name "*.mpa" -type f >> ~/Desktop/Script.log
    find / -name "*.abs" -type f >> ~/Desktop/Script.log
    find / -name "*.mpega" -type f >> ~/Desktop/Script.log
    find / -name "*.au" -type f >> ~/Desktop/Script.log
    find / -name "*.snd" -type f >> ~/Desktop/Script.log
    find / -name "*.wav" -type f >> ~/Desktop/Script.log
    find / -name "*.aiff" -type f >> ~/Desktop/Script.log
    find / -name "*.aif" -type f >> ~/Desktop/Script.log
    find / -name "*.sid" -type f >> ~/Desktop/Script.log
    find / -name "*.flac" -type f >> ~/Desktop/Script.log
    find / -name "*.ogg" -type f >> ~/Desktop/Script.log
    clear
    printTime "All audio files has been listed."

    find / -name "*.mpeg" -type f >> ~/Desktop/Script.log
    find / -name "*.mpg" -type f >> ~/Desktop/Script.log
    find / -name "*.mpe" -type f >> ~/Desktop/Script.log
    find / -name "*.dl" -type f >> ~/Desktop/Script.log
    find / -name "*.movie" -type f >> ~/Desktop/Script.log
    find / -name "*.movi" -type f >> ~/Desktop/Script.log
    find / -name "*.mv" -type f >> ~/Desktop/Script.log
    find / -name "*.iff" -type f >> ~/Desktop/Script.log
    find / -name "*.anim5" -type f >> ~/Desktop/Script.log
    find / -name "*.anim3" -type f >> ~/Desktop/Script.log
    find / -name "*.anim7" -type f >> ~/Desktop/Script.log
    find / -name "*.avi" -type f >> ~/Desktop/Script.log
    find / -name "*.vfw" -type f >> ~/Desktop/Script.log
    find / -name "*.avx" -type f >> ~/Desktop/Script.log
    find / -name "*.fli" -type f >> ~/Desktop/Script.log
    find / -name "*.flc" -type f >> ~/Desktop/Script.log
    find / -name "*.mov" -type f >> ~/Desktop/Script.log
    find / -name "*.qt" -type f >> ~/Desktop/Script.log
    find / -name "*.spl" -type f >> ~/Desktop/Script.log
    find / -name "*.swf" -type f >> ~/Desktop/Script.log
    find / -name "*.dcr" -type f >> ~/Desktop/Script.log
    find / -name "*.dir" -type f >> ~/Desktop/Script.log
    find / -name "*.dxr" -type f >> ~/Desktop/Script.log
    find / -name "*.rpm" -type f >> ~/Desktop/Script.log
    find / -name "*.rm" -type f >> ~/Desktop/Script.log
    find / -name "*.smi" -type f >> ~/Desktop/Script.log
    find / -name "*.ra" -type f >> ~/Desktop/Script.log
    find / -name "*.ram" -type f >> ~/Desktop/Script.log
    find / -name "*.rv" -type f >> ~/Desktop/Script.log
    find / -name "*.wmv" -type f >> ~/Desktop/Script.log
    find / -name "*.asf" -type f >> ~/Desktop/Script.log
    find / -name "*.asx" -type f >> ~/Desktop/Script.log
    find / -name "*.wma" -type f >> ~/Desktop/Script.log
    find / -name "*.wax" -type f >> ~/Desktop/Script.log
    find / -name "*.wmv" -type f >> ~/Desktop/Script.log
    find / -name "*.wmx" -type f >> ~/Desktop/Script.log
    find / -name "*.3gp" -type f >> ~/Desktop/Script.log
    find / -name "*.mov" -type f >> ~/Desktop/Script.log
    find / -name "*.mp4" -type f >> ~/Desktop/Script.log
    find / -name "*.avi" -type f >> ~/Desktop/Script.log
    find / -name "*.swf" -type f >> ~/Desktop/Script.log
    find / -name "*.flv" -type f >> ~/Desktop/Script.log
    find / -name "*.m4v" -type f >> ~/Desktop/Script.log
    clear
    printTime "All video files have been listed."

    find / -name "*.tiff" -type f >> ~/Desktop/Script.log
    find / -name "*.tif" -type f >> ~/Desktop/Script.log
    find / -name "*.rs" -type f >> ~/Desktop/Script.log
    find / -name "*.im1" -type f >> ~/Desktop/Script.log
    find / -name "*.gif" -type f >> ~/Desktop/Script.log
    find / -name "*.jpeg" -type f >> ~/Desktop/Script.log
    find / -name "*.jpg" -type f >> ~/Desktop/Script.log
    find / -name "*.jpe" -type f >> ~/Desktop/Script.log
    find / -name "*.png" -type f >> ~/Desktop/Script.log
    find / -name "*.rgb" -type f >> ~/Desktop/Script.log
    find / -name "*.xwd" -type f >> ~/Desktop/Script.log
    find / -name "*.xpm" -type f >> ~/Desktop/Script.log
    find / -name "*.ppm" -type f >> ~/Desktop/Script.log
    find / -name "*.pbm" -type f >> ~/Desktop/Script.log
    find / -name "*.pgm" -type f >> ~/Desktop/Script.log
    find / -name "*.pcx" -type f >> ~/Desktop/Script.log
    find / -name "*.ico" -type f >> ~/Desktop/Script.log
    find / -name "*.svg" -type f >> ~/Desktop/Script.log
    find / -name "*.svgz" -type f >> ~/Desktop/Script.log
    clear
    printTime "All image files have been listed."
    else
    echo Response not recognized.
    fi
    printTime "Media files are complete."

    clear
    find / -type f -perm 777 >> ~/Desktop/Script.log
    find / -type f -perm 776 >> ~/Desktop/Script.log
    find / -type f -perm 775 >> ~/Desktop/Script.log
    find / -type f -perm 774 >> ~/Desktop/Script.log
    find / -type f -perm 773 >> ~/Desktop/Script.log
    find / -type f -perm 772 >> ~/Desktop/Script.log
    find / -type f -perm 771 >> ~/Desktop/Script.log
    find / -type f -perm 770 >> ~/Desktop/Script.log
    find / -type f -perm 767 >> ~/Desktop/Script.log
    find / -type f -perm 766 >> ~/Desktop/Script.log
    find / -type f -perm 765 >> ~/Desktop/Script.log
    find / -type f -perm 764 >> ~/Desktop/Script.log
    find / -type f -perm 763 >> ~/Desktop/Script.log
    find / -type f -perm 762 >> ~/Desktop/Script.log
    find / -type f -perm 761 >> ~/Desktop/Script.log
    find / -type f -perm 760 >> ~/Desktop/Script.log
    find / -type f -perm 757 >> ~/Desktop/Script.log
    find / -type f -perm 756 >> ~/Desktop/Script.log
    find / -type f -perm 755 >> ~/Desktop/Script.log
    find / -type f -perm 754 >> ~/Desktop/Script.log
    find / -type f -perm 753 >> ~/Desktop/Script.log
    find / -type f -perm 752 >> ~/Desktop/Script.log
    find / -type f -perm 751 >> ~/Desktop/Script.log
    find / -type f -perm 750 >> ~/Desktop/Script.log
    find / -type f -perm 747 >> ~/Desktop/Script.log
    find / -type f -perm 746 >> ~/Desktop/Script.log
    find / -type f -perm 745 >> ~/Desktop/Script.log
    find / -type f -perm 744 >> ~/Desktop/Script.log
    find / -type f -perm 743 >> ~/Desktop/Script.log
    find / -type f -perm 742 >> ~/Desktop/Script.log
    find / -type f -perm 741 >> ~/Desktop/Script.log
    find / -type f -perm 740 >> ~/Desktop/Script.log
    find / -type f -perm 737 >> ~/Desktop/Script.log
    find / -type f -perm 736 >> ~/Desktop/Script.log
    find / -type f -perm 735 >> ~/Desktop/Script.log
    find / -type f -perm 734 >> ~/Desktop/Script.log
    find / -type f -perm 733 >> ~/Desktop/Script.log
    find / -type f -perm 732 >> ~/Desktop/Script.log
    find / -type f -perm 731 >> ~/Desktop/Script.log
    find / -type f -perm 730 >> ~/Desktop/Script.log
    find / -type f -perm 727 >> ~/Desktop/Script.log
    find / -type f -perm 726 >> ~/Desktop/Script.log
    find / -type f -perm 725 >> ~/Desktop/Script.log
    find / -type f -perm 724 >> ~/Desktop/Script.log
    find / -type f -perm 723 >> ~/Desktop/Script.log
    find / -type f -perm 722 >> ~/Desktop/Script.log
    find / -type f -perm 721 >> ~/Desktop/Script.log
    find / -type f -perm 720 >> ~/Desktop/Script.log
    find / -type f -perm 717 >> ~/Desktop/Script.log
    find / -type f -perm 716 >> ~/Desktop/Script.log
    find / -type f -perm 715 >> ~/Desktop/Script.log
    find / -type f -perm 714 >> ~/Desktop/Script.log
    find / -type f -perm 713 >> ~/Desktop/Script.log
    find / -type f -perm 712 >> ~/Desktop/Script.log
    find / -type f -perm 711 >> ~/Desktop/Script.log
    find / -type f -perm 710 >> ~/Desktop/Script.log
    find / -type f -perm 707 >> ~/Desktop/Script.log
    find / -type f -perm 706 >> ~/Desktop/Script.log
    find / -type f -perm 705 >> ~/Desktop/Script.log
    find / -type f -perm 704 >> ~/Desktop/Script.log
    find / -type f -perm 703 >> ~/Desktop/Script.log
    find / -type f -perm 702 >> ~/Desktop/Script.log
    find / -type f -perm 701 >> ~/Desktop/Script.log
    find / -type f -perm 700 >> ~/Desktop/Script.log
    printTime "All files with file permissions between 700 and 777 have been listed above."

    clear
    find / -name "*.php" -type f >> ~/Desktop/Script.log
    printTime "All PHP files have been listed above. ('/var/cache/dictionaries-common/sqspell.php' is a system PHP file)"

    clear
    apt-get purge netcat -y -qq
    apt-get purge netcat-openbsd -y -qq
    apt-get purge netcat-traditional -y -qq
    apt-get purge ncat -y -qq
    apt-get purge pnetcat -y -qq
    apt-get purge socat -y -qq
    apt-get purge sock -y -qq
    apt-get purge socket -y -qq
    apt-get purge sbd -y -qq
    rm /usr/bin/nc
    clear
    printTime "Netcat and all other instances have been removed."

    apt-get purge john -y -qq
    apt-get purge john-data -y -qq
    clear
    printTime "John the Ripper has been removed."

    apt-get purge hydra -y -qq
    apt-get purge hydra-gtk -y -qq
    clear
    printTime "Hydra has been removed."

    apt-get purge aircrack-ng -y -qq
    clear
    printTime "Aircrack-NG has been removed."

    apt-get purge fcrackzip -y -qq
    clear
    printTime "FCrackZIP has been removed."

    apt-get purge lcrack -y -qq
    clear
    printTime "LCrack has been removed."

    apt-get purge ophcrack -y -qq
    apt-get purge ophcrack-cli -y -qq
    clear
    printTime "OphCrack has been removed."

    apt-get purge pdfcrack -y -qq
    clear
    printTime "PDFCrack has been removed."

    apt-get purge pyrit -y -qq
    clear
    printTime "Pyrit has been removed."

    apt-get purge rarcrack -y -qq
    clear
    printTime "RARCrack has been removed."

    apt-get purge sipcrack -y -qq
    clear
    printTime "SipCrack has been removed."

    apt-get purge irpas -y -qq
    clear
    printTime "IRPAS has been removed."

    clear
    printTime 'Are there any hacking tools shown? (not counting libcrack2:amd64 or cracklib-runtime)'
    dpkg -l | egrep "crack|hack" >> ~/Desktop/Script.log

    apt-get purge logkeys -y -qq
    clear
    printTime "LogKeys has been removed."

    apt-get purge zeitgeist-core -y -qq
    apt-get purge zeitgeist-datahub -y -qq
    apt-get purge python-zeitgeist -y -qq
    apt-get purge rhythmbox-plugin-zeitgeist -y -qq
    apt-get purge zeitgeist -y -qq
    printTime "Zeitgeist has been removed."

    apt-get purge nfs-kernel-server -y -qq
    apt-get purge nfs-common -y -qq
    apt-get purge portmap -y -qq
    apt-get purge rpcbind -y -qq
    apt-get purge autofs -y -qq
    printTime "NFS has been removed."

    apt-get purge nginx -y -qq
    apt-get purge nginx-common -y -qq
    printTime "NGINX has been removed."

    apt-get purge inetd -y -qq
    apt-get purge openbsd-inetd -y -qq
    apt-get purge xinetd -y -qq
    apt-get purge inetutils-ftp -y -qq
    apt-get purge inetutils-ftpd -y -qq
    apt-get purge inetutils-inetd -y -qq
    apt-get purge inetutils-ping -y -qq
    apt-get purge inetutils-syslogd -y -qq
    apt-get purge inetutils-talk -y -qq
    apt-get purge inetutils-talkd -y -qq
    apt-get purge inetutils-telnet -y -qq
    apt-get purge inetutils-telnetd -y -qq
    apt-get purge inetutils-tools -y -qq
    apt-get purge inetutils-traceroute -y -qq
    printTime "Inetd (super-server) and all inet utilities have been removed."

    clear
    apt-get purge vnc4server -y -qq
    apt-get purge vncsnapshot -y -qq
    apt-get purge vtgrab -y -qq
    printTime "VNC has been removed."

    clear
    apt-get purge snmp -y -qq
    printTime "SNMP has been removed."

    clear
    cp /etc/login.defs ~/Desktop/backups/
    sed -i '160s/.*/PASS_MAX_DAYS\o01130/' /etc/login.defs
    sed -i '161s/.*/PASS_MIN_DAYS\o0113/' /etc/login.defs
    sed -i '162s/.*/PASS_MIN_LEN\o0118/' /etc/login.defs
    sed -i '163s/.*/PASS_WARN_AGE\o0117/' /etc/login.defs
    printTime "Password policies have been set with /etc/login.defs."

    clear
    apt-get install libpam-cracklib -y -qq
    cp /etc/pam.d/common-auth ~/Desktop/backups/
    cp /etc/pam.d/common-password ~/Desktop/backups/
    echo -e "#\n# /etc/pam.d/common-auth - authentication settings common to all services\n#\n# This file is included from other service-specific PAM config files,\n# and should contain a list of the authentication modules that define\n# the central authentication scheme for use on the system\n# (e.g., /etc/shadow, LDAP, Kerberos, etc.).  The default is to use the\n# traditional Unix authentication mechanisms.\n#\n# As of pam 1.0.1-6, this file is managed by pam-auth-update by default.\n# To take advantage of this, it is recommended that you configure any\n# local modules either before or after the default block, and use\n# pam-auth-update to manage selection of other modules.  See\n# pam-auth-update(8) for details.\n\n# here are the per-package modules (the \"Primary\" block)\nauth	[success=1 default=ignore]	pam_unix.so nullok_secure\n# here's the fallback if no module succeeds\nauth	requisite			pam_deny.so\n# prime the stack with a positive return value if there isn't one already;\n# this avoids us returning an error just because nothing sets a success code\n# since the modules above will each just jump around\nauth	required			pam_permit.so\n# and here are more per-package modules (the \"Additional\" block)\nauth	optional			pam_cap.so \n# end of pam-auth-update config\nauth required pam_tally2.so deny=5 unlock_time=1800 onerr=fail audit even_deny_root_account silent" > /etc/pam.d/common-auth
    echo -e "#\n# /etc/pam.d/common-password - password-related modules common to all services\n#\n# This file is included from other service-specific PAM config files,\n# and should contain a list of modules that define the services to be\n# used to change user passwords.  The default is pam_unix.\n\n# Explanation of pam_unix options:\n#\n# The \"sha512\" option enables salted SHA512 passwords.  Without this option,\n# the default is Unix crypt.  Prior releases used the option \"md5\".\n#\n# The \"obscure\" option replaces the old \`OBSCURE_CHECKS_ENAB\' option in\n# login.defs.\n#\n# See the pam_unix manpage for other options.\n\n# As of pam 1.0.1-6, this file is managed by pam-auth-update by default.\n# To take advantage of this, it is recommended that you configure any\n# local modules either before or after the default block, and use\n# pam-auth-update to manage selection of other modules.  See\n# pam-auth-update(8) for details.\n\n# here are the per-package modules (the \"Primary\" block)\npassword	[success=1 default=ignore]	pam_unix.so obscure sha512\n# here's the fallback if no module succeeds\npassword	requisite			pam_deny.so\n# prime the stack with a positive return value if there isn't one already;\n# this avoids us returning an error just because nothing sets a success code\n# since the modules above will each just jump around\npassword	required			pam_permit.so\n# and here are more per-package modules (the \"Additional\" block)\npassword	optional	pam_gnome_keyring.so \n# end of pam-auth-update config" > /etc/pam.d/common-password
    printTime "If password policies are not correctly configured, try this for /etc/pam.d/common-password:\npassword requisite pam_cracklib.so retry=3 minlen=8 difok=3 reject_username minclass=3 maxrepeat=2 dcredit=1 ucredit=1 lcredit=1 ocredit=1\npassword requisite pam_pwhistory.so use_authtok remember=24 enforce_for_root"
    printTime "Password policies have been set with and /etc/pam.d."

    clear
    apt-get install iptables -y -qq
    iptables -A INPUT -p all -s localhost  -i eth0 -j DROP
    printTime "All outside packets from internet claiming to be from loopback are denied."

    clear
    cp /etc/init/control-alt-delete.conf ~/Desktop/backups/
    sed '/^exec/ c\exec false' /etc/init/control-alt-delete.conf
    printTime "Reboot using Ctrl-Alt-Delete has been disabled."

    clear
    apt-get install apparmor apparmor-profiles -y -qq
    printTime "AppArmor has been installed."

    clear
    crontab -l > ~/Desktop/backups/crontab-old
    crontab -r
    printTime "Crontab has been backed up. All startup tasks have been removed from crontab."

    clear
    cd /etc/
    /bin/rm -f cron.deny at.deny
    echo root >cron.allow
    echo root >at.allow
    /bin/chown root:root cron.allow at.allow
    /bin/chmod 400 cron.allow at.allow
    cd ..
    printTime "Only root allowed in cron."

    clear
    chmod 777 /etc/apt/apt.conf.d/10periodic
    cp /etc/apt/apt.conf.d/10periodic ~/Desktop/backups/
    echo -e "APT::Periodic::Update-Package-Lists \"1\";\nAPT::Periodic::Download-Upgradeable-Packages \"1\";\nAPT::Periodic::AutocleanInterval \"1\";\nAPT::Periodic::Unattended-Upgrade \"1\";" > /etc/apt/apt.conf.d/10periodic
    chmod 644 /etc/apt/apt.conf.d/10periodic
    printTime "Daily update checks, download upgradeable packages, autoclean interval, and unattended upgrade enabled."

    clear
    if [[ $(lsb_release -r) == "Release:	14.04" ]] || [[ $(lsb_release -r) == "Release:	14.10" ]]
    then
    chmod 777 /etc/apt/sources.list
    cp /etc/apt/sources.list ~/Desktop/backups/
    echo -e "deb http://us.archive.ubuntu.com/ubuntu/ trusty main restricted universe multiverse\ndeb-src http://us.archive.ubuntu.com/ubuntu/ trusty main restricted universe multiverse\ndeb http://us.archive.ubuntu.com/ubuntu/ trusty-security main restricted universe multiverse\ndeb http://us.archive.ubuntu.com/ubuntu/ trusty-updates main restricted universe multiverse\ndeb http://us.archive.ubuntu.com/ubuntu/ trusty-proposed main restricted universe multiverse\ndeb-src http://us.archive.ubuntu.com/ubuntu/ trusty-security main restricted universe multiverse\ndeb-src http://us.archive.ubuntu.com/ubuntu/ trusty-updates main restricted universe multiverse\ndeb-src http://us.archive.ubuntu.com/ubuntu/ trusty-proposed main restricted universe multiverse" > /etc/apt/sources.list
    chmod 644 /etc/apt/sources.list
    elif [[ $(lsb_release -r) == "Release:	12.04" ]] || [[ $(lsb_release -r) == "Release:	12.10" ]]
    then
    chmod 777 /etc/apt/sources.list
    cp /etc/apt/sources.list ~/Desktop/backups/
    echo -e "deb http://us.archive.ubuntu.com/ubuntu/ precise main restricted universe multiverse \ndeb-src http://us.archive.ubuntu.com/ubuntu/ precise main restricted universe multiverse \ndeb http://us.archive.ubuntu.com/ubuntu/ precise-security main restricted universe multiverse\ndeb http://us.archive.ubuntu.com/ubuntu/ precise-updates main restricted universe multiverse\ndeb http://us.archive.ubuntu.com/ubuntu/ precise-proposed main restricted universe multiverse\ndeb-src http://us.archive.ubuntu.com/ubuntu/ precise-security main restricted universe multiverse\ndeb-src http://us.archive.ubuntu.com/ubuntu/ precise-updates main restricted universe multiverse\ndeb-src http://us.archive.ubuntu.com/ubuntu/ precise-proposed main restricted universe multiverse" > /etc/apt/sources.list
    chmod 644 /etc/apt/sources.list
    else
    echo “Error, cannot detect OS version”
    fi
    printTime "Apt Repositories have been added."

    clear
    apt-get update -qq
    apt-get upgrade -qq
    apt-get dist-upgrade -qq
    printTime "Ubuntu OS has checked for updates and has been upgraded."

    clear
    apt-get autoremove -y -qq
    apt-get autoclean -y -qq
    apt-get clean -y -qq
    printTime "All unused packages have been removed."

    clear
    echo "Check to verify that all update settings are correct."
    update-manager

    clear
    apt-get update
    apt-get upgrade openssl libssl-dev
    apt-cache policy openssl libssl-dev
    printTime "OpenSSL heart bleed bug has been fixed."

    clear
    if [[ $(grep root /etc/passwd | wc -l) -gt 1 ]]
    then
    grep root /etc/passwd | wc -l
    echo -e "UID 0 is not correctly set to root. Please fix.\nPress enter to continue..."
    read waiting
    else
    printTime "UID 0 is correctly set to root."
    fi

    clear
    mkdir -p ~/Desktop/logs
    chmod 777 ~/Desktop/logs
    printTime "Logs folder has been created on the Desktop."

    clear
    touch ~/Desktop/logs/allusers.txt
    uidMin=$(grep "^UID_MIN" /etc/login.defs)
    uidMax=$(grep "^UID_MAX" /etc/login.defs)
    echo -e "User Accounts:" >> ~/Desktop/logs/allusers.txt
    awk -F':' -v "min=${uidMin##UID_MIN}" -v "max=${uidMax##UID_MAX}" '{ if ( $3 >= min && $3 <= max  && $7 != "/sbin/nologin" ) print $0 }' /etc/passwd >> ~/Desktop/logs/allusers.txt
    echo -e "\nSystem Accounts:" >> ~/Desktop/logs/allusers.txt
    awk -F':' -v "min=${uidMin##UID_MIN}" -v "max=${uidMax##UID_MAX}" '{ if ( !($3 >= min && $3 <= max  && $7 != "/sbin/nologin")) print $0 }' /etc/passwd >> ~/Desktop/logs/allusers.txt
    printTime "All users have been logged."
    cp /etc/services ~/Desktop/logs/allports.log
    printTime "All ports log has been created."
    dpkg -l > ~/Desktop/logs/packages.log
    printTime "All packages log has been created."
    apt-mark showmanual > ~/Desktop/logs/manuallyinstalled.log
    printTime "All manually instealled packages log has been created."
    service --status-all > ~/Desktop/logs/allservices.txt
    printTime "All running services log has been created."
    ps ax > ~/Desktop/logs/processes.log
    printTime "All running processes log has been created."
    ss -l > ~/Desktop/logs/socketconnections.log
    printTime "All socket connections log has been created."
    sudo netstat -tlnp > ~/Desktop/logs/listeningports.log
    printTime "All listening ports log has been created."
    cp /var/log/auth.log ~/Desktop/logs/auth.log
    printTime "Auth log has been created."
    cp /var/log/syslog ~/Desktop/logs/syslog.log
    printTime "System log has been created."

    clear
    apt-get install tree -y -qq
    apt-get install diffuse -y -qq
    mkdir Desktop/Comparatives
    chmod 777 Desktop/Comparatives

    cp /etc/apt/apt.conf.d/10periodic Desktop/Comparatives/
    cp Desktop/logs/allports.log Desktop/Comparatives/
    cp Desktop/logs/allservices.txt Desktop/Comparatives/
    touch Desktop/Comparatives/alltextfiles.txt
    find . -type f -exec grep -Iq . {} \; -and -print >> Desktop/Comparatives/alltextfiles.txt
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
    printTime "Tree and Diffuse have been installed, files on current system have been copied for comparison."

    chmod 777 -R Desktop/Comparatives/
    chmod 777 -R Desktop/backups
    chmod 777 -R Desktop/logs

    clear
    printTime "Script is complete."
}
#RHhakTools() {
	##Redo all of the hak tools function just for fedora

#}

##Edits the sysctl.conf file
sys() {
	##Disables IPv6
	sed -i '$a net.ipv6.conf.all.disable_ipv6 = 1' /etc/sysctl.conf
	sed -i '$a net.ipv6.conf.default.disable_ipv6 = 1' /etc/sysctl.conf
	sed -i '$a net.ipv6.conf.lo.disable_ipv6 = 1' /etc/sysctl.conf

	##Disables IP Spoofing
	sed -i '$a net.ipv4.conf.all.rp_filter=1' /etc/sysctl.conf

	##Disables IP source routing
	sed -i '$a net.ipv4.conf.all.accept_source_route=0' /etc/sysctl.conf

	##SYN Flood Protection
	sed -i '$a net.ipv4.tcp_max_syn_backlog = 2048' /etc/sysctl.conf
	sed -i '$a net.ipv4.tcp_synack_retries = 2' /etc/sysctl.conf
	sed -i '$a net.ipv4.tcp_syn_retries = 5' /etc/sysctl.conf
	sed -i '$a net.ipv4.tcp_syncookies=1' /etc/sysctl.conf

	##IP redirecting is disallowed
	sed -i '$a net.ipv4.ip_foward=0' /etc/sysctl.conf
	sed -i '$a net.ipv4.conf.all.send_redirects=0' /etc/sysctl.conf
	sed -i '$a net.ipv4.conf.default.send_redirects=0' /etc/sysctl.conf

	sysctl -p
	pause
}

##Lists the running processes
proc() {
	lsof -Pnl +M -i > runningProcesses.log
	##Removing the default running processes
	sed -i '/avahi-dae/ d' runningProcesses.log
	sed -i '/cups-brow/ d' runningProcesses.log
	sed -i '/dhclient/ d' runningProcesses.log
	sed -i '/dnsmasq/ d' runningProcesses.log
	sed -i '/cupsd/ d' runningProcesses.log

	pause
}

##Searches for netcat and its startup script and comments out the lines
nc(){

grep -i 'nc|netcat'
if [ $? -eq 0 ]
then
	cat runningProcesses.log
		read -p "What is the name of the suspected netcat?[none]: " nc
			if [ $nc == "none"]
			then
				echo "k xd"
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
	pause
}

##Exports the /etc/sudoers file and checks for a timeout and NOPASSWD value
sudoers() {

	cat /etc/sudoers | grep NOPASSWD.* >> /dev/null
	if [ $? -eq 0 ]
	then
		echo "## NOPASSWD VALUE HAS BEEN FOUND IN THE SUDOERS FILE, GO CHANGE IT." >> postScript.log
	fi
	##Looks for a timeout value and and delete is.
	cat /etc/sudoers | grep timestamp_timeout >> /dev/null
	if [ $? -eq 0 ]
	then
		TIME=`cat /etc/sudoers | grep timestamp_timeout | cut -f2 | cut -d= -f2`
		echo "## Time out value has been set to $TIME Please go change it or remove it." >> postScript
	fi

	pause
}

##Lists all the cron jobs, init, init.d
cron() {

#	Listing all the cronjobs
	echo "###CRONTABS###" > cron.log
	for x in $(cat users); do crontab -u $x -l; done >> cron.log
	echo "###CRON JOBS###" >> cron.log
	ls /etc/cron.* >> cron.log
	ls /var/spool/cron/crontabs/.* >> cron.log
	ls /etc/crontab >> cron.log

#	Listing the init.d/init files
	echo "###Init.d###" >> cron.log
	ls /etc/init.d >> cron.log

	echo "###Init###" >> cron.log
	ls /etc/init >> cron.log
	cat cron.log
	pause
}

CAD() {
	sed -i '/exec shutdown -r not "Control-Alt-Delete pressed"/#exec shutdown -r not "Control-Alt-Delete pressed"/' /etc/init/control-alt-delete.conf
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
				echo "~~~~~~~~~~~~~~~~Written by: Ethan Fowler Team-ByTE~~~~~~~~~~~~~~~~~~~~~~~~"
				echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
				echo " "
				echo "1) Update the machine.			2) Set automatic updates."
				echo "3) Search for prohibited file.		4) configure the firewall."
				echo "5) Configure login screen.		6) Create any new users."
				echo "7) Change all the passwords.		8) Delete any users."
				echo "9) Set all the admins.			10) List all cronjobs."
				echo "11) Set the password policy.		12) Set the lockout policy."
				echo "13) Remove the hacking tools.		14) Configure SSH."
				echo "15) Edit the sysctl.conf.			16) Export the sudoers file."
				echo "17) List all running processes.	18) Remove NetCat."
				echo "19) Reboot the machine.			20) Secure the root account"
				echo "21) PostScript				    22)Disable ctrl-alt-del"
				echo "23) Beirman               		24)Exit"
	;;
	"Debian")
				echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
				echo "		 ██████╗ ███████╗██████╗  █████╗ ██╗███╗   ██╗			"
				echo "		 ██╔══██╗██╔════╝██╔══██╗██╔══██╗██║████╗  ██║			"
				echo "		 ██║  ██║█████╗  ██████╔╝███████║██║██╔██╗ ██║			"
				echo "		 ██║  ██║██╔══╝  ██╔══██╗██╔══██║██║██║╚██╗██║			"
				echo "		 ██████╔╝███████╗██████╔╝██║  ██║██║██║ ╚████║			"
				echo "	     ╚═════╝ ╚══════╝╚═════╝ ╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝			"
				echo "~~~~~~~~~~~~~~~~Written by: Ethan Fowler Team-ByTE~~~~~~~~~~~~~~~~~~~~~~~~"
				echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
				echo " "
				echo "1) Update the machine.                    2) Set automatic updates."
				echo "3) Search for prohibited file.            4) configure the firewall."
				echo "5) Configure login screen.                6) Create any new users."
				echo "7) Change all the passwords.              8) Delete any users."
				echo "9) Set all the admins.                    10) List all cronjobs."
				echo "11) Set the password policy.              12) Set the lockout policy."
				echo "13) Remove the hacking tools.             14) Configure SSH."
				echo "15) Edit the sysctl.conf.                 16) Export the sudoers file."
				echo "17) List all running processes.           18) Remove NetCat."
				echo "19) Reboot the machine.                   20) Secure the root account"
				echo "21) PostScript                            22) Disable ctrl-alt-del"
				echo "23) Disable Virtual Terminals     	24) Exit"
	;;
	"RedHat")
				echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
				echo "			██████╗ ███████╗██████╗ ██╗  ██╗ █████╗ ████████╗				"
				echo "			██╔══██╗██╔════╝██╔══██╗██║  ██║██╔══██╗╚══██╔══╝				"
				echo "			██████╔╝█████╗  ██║  ██║███████║███████║   ██║   				"
				echo "			██╔══██╗██╔══╝  ██║  ██║██╔══██║██╔══██║   ██║   				"
				echo "			██║  ██║███████╗██████╔╝██║  ██║██║  ██║   ██║   				"
				echo "			╚═╝  ╚═╝╚══════╝╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝   				"
				echo "~~~~~~~~~~~~~~~~Written by: Ethan Fowler Team-ByTE~~~~~~~~~~~~~~~~~~~~~~~~"
                echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
                echo " "
			##NOT ALL OF THESE WORK YET, NEED TO FIX
                echo "1) Update the machine.                    2) Set automatic updates."
                echo "3) Search for prohibited file.            4) configure the firewall."
                echo "5) Configure login screen.                6) Create any new users."
                echo "7) Change all the passwords.              8) Delete any users."
                echo "9) Set all the admins.                    10) List all cronjobs."
                echo "11) #Set the password policy.              12) Set the lockout policy."
                echo "13) #Remove the hacking tools.             14) #Configure SSH."
                echo "15) Edit the sysctl.conf.                 16) Export the sudoers file."
                echo "17) List all running processes.           18) #Remove NetCat."
                echo "19) Reboot the machine.                   20) Secure the root account"
                echo "21) PostScript                            22) Disable ctrl-alt-del"
                echo "23) Disable Virtual Terminals     	24) Exit"
	;;
	"CentOS")
				echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
				echo "			 ██████╗███████╗███╗   ██╗████████╗ ██████╗ ███████╗			"
				echo "			██╔════╝██╔════╝████╗  ██║╚══██╔══╝██╔═══██╗██╔════╝			"
				echo "			██║     █████╗  ██╔██╗ ██║   ██║   ██║   ██║███████╗			"
				echo "			██║     ██╔══╝  ██║╚██╗██║   ██║   ██║   ██║╚════██║			"
				echo "			╚██████╗███████╗██║ ╚████║   ██║   ╚██████╔╝███████║			"
				echo " 	  	     ╚═════╝╚══════╝╚═╝  ╚═══╝   ╚═╝    ╚═════╝ ╚══════╝			"
                echo "~~~~~~~~~~~~~~~~Written by: Ethan Fowler Team-ByTE~~~~~~~~~~~~~~~~~~~~~~~~"
                echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
                echo " "
                ##NOT ALL OF THESE WORK YET, NEED TO FIX
                echo "1) Update the machine.                    2) Set automatic updates."
                echo "3) Search for prohibited file.            4) configure the firewall."
                echo "5) Configure login screen.                6) Create any new users."
                echo "7) Change all the passwords.              8) Delete any users."
                echo "9) Set all the admins.                    10) List all cronjobs."
                echo "11) #Set the password policy.              12) Set the lockout policy."
                echo "13) #Remove the hacking tools.             14) #Configure SSH."
                echo "15) Edit the sysctl.conf.                 16) Export the sudoers file."
                echo "17) List all running processes.           18) #Remove NetCat."
                echo "19) Reboot the machine.                   20) Secure the root account"
                echo "21) PostScript                            22) Disable ctrl-alt-del"
                echo "23) Disable Virtual Terminals    		24) Exit"
	;;
	esac

}

read_options(){
	case $opsys in
	"Ubuntu"|"Debian")
		local choice
		read -p "Pease select item you wish to do: " choice

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
			21) cat postScript; pause;;
			22) CAD;;
            23) Beirman;;
			24) exit20;;
			69)runFull;;
			*) echo "Sorry that is not an option please select another one..."
			;;
		esac
	;;
	"CentOS")
		local choice
		read -p "Pease select item you wish to do: " choice

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
			21) cat postScript; pause;;
			22) CAD;;
			24) exit20;;
			69)runFull;;
			*) echo "Sorry that is not an option please select another one..."
			;;
		esac
	;;
	"RedHat")
		local choice
		read -p "Pease select item you wish to do: " choice

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
			21) cat postScript; pause;;
			22) CAD;;
			24) exit20;;
			69)runFull;;
			*) echo "Sorry that is not an option please select another one..."
			;;
		esac
	;;

	esac
}

##This runs .the actual script
while true
do
	clear
	show_menu
	read_options
done
