sudo apt install -y ansible
    sudo sh -c "echo '- src: https://github.com/florianutz/Ubuntu2004-CIS.git' > /etc/ansible/requirements.yml"
    cd /etc/ansible/
    sudo ansible-galaxy install -p roles -r /etc/ansible/requirements.yml
    sudo sh -c "cat > /etc/ansible/harden.yml <<EOF
    - name: Harden Server
      hosts: localhost
      connection: local
      become: yes

      roles:
        - Ubuntu2004-CIS

    EOF
    "
    nano /etc/ansible/roles/Ubuntu1804-CIS/defaults/main.yml
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