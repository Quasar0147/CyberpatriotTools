## Perhaps nova is right, KEEP THIS SIMPLE

# Sysctl checks
nano /etc/sysctl.conf
rm /etc/sysctl.d/*.conf /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf
# Pam
nano /etc/pam.d/* /etc/pam.conf


# Sudoers
nano /etc/sudoers /etc/sudoers.d/* /etc/sudo.conf

# Systemd
nano /etc/systemd/*.conf

# GDM3
nano /etc/gdm3/custom.conf
nano /etc/gdm3/greeter.dconf-defaults
nano /etc/dconf/db/gdm.d/*


