sudo apt install -y ansible
    sudo sh -c "echo '- src: https://github.com/beholdenkey/ansible-role-ubuntu2004-stig.git' > /etc/ansible/requirements.yml"
    cd /etc/ansible/
    sudo ansible-galaxy install -p roles -r /etc/ansible/requirements.yml
    sudo sh -c "cat > /etc/ansible/harden2.yml <<EOF
    - name: Harden Server
      hosts: localhost
      connection: local
      become: yes

      roles:
        - ansible-role-ubuntu2004-stig

    EOF
    "
    nano /etc/ansible/roles/ansible-role-ubuntu2004-stig/blob/devel/defaults/main.yml
    read -p "Enter y to continue and STIG harden, btw this might kill you : D. Enter anything else to skip to compliance checks" a
    if [ $a = y ]
    then
    sudo ansible-playbook /etc/ansible/harden2.yml
    fi
