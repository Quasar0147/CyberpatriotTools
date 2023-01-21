dnf install firewalld
systemctl enable firewalld
systemctl start firewalld
# Configure firewalld
# Deny all incoming traffic
firewall-cmd --set-default-zone=drop
# Deny All Outgoing Traffic
firewall-cmd --zone=drop --add-rich-rule='rule family=ipv4 source address=0.0.0.0/0 drop'
