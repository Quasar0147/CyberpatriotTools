# DISA STIG for Canonical Ubuntu 20.04 LTS

Ansible Role for DISA STIG for Ubuntu 20.04 LTS
  
Profile Description:  
This profile contains configuration checks that align to the  
DISA STIG for Ubuntu 20.04 LTS V1R1.  
In addition to being applicable to Ubuntu 20.04 LTS, DISA recognizes this  
configuration baseline as applicable to the operating system tier of  
Red Hat technologies that are based on Ubuntu 20.04 LTS, such as:  

- Ubuntu 20.04 Linux Server  
- Ubuntu 20.04 Workstation and Desktop
- Ubuntu 20.04 Containers with a Ubuntu 20.04 LTS image

The tasks that are used in this role are generated using OpenSCAP.
See the OpenSCAP project for more details on Ansible playbook generation at [https://github.com/OpenSCAP/openscap](https://github.com/OpenSCAP/openscap)

To submit a fix or enhancement for an Ansible task that is failing or missing in this role,
see the ComplianceAsCode project at [https://github.com/ComplianceAsCode/content](https://github.com/ComplianceAsCode/content)

## Requirements

- Ansible version 2.9 or higher

## Role Variables

To customize the role to your liking, check out the [list of variables](defaults/main.yml).

## Dependencies

N/A

## Example Role Usage

Run `ansible-galaxy install ubuntu2004_stig` to
download and install the role. Then, you can use the following playbook snippet to run the Ansible role:

    - hosts: all
      roles:
         - { role: ubuntu2004_stig }

Next, check the playbook using (on the localhost) the following example:

    ansible-playbook -i "localhost," -c local --check playbook.yml

To deploy it, use (this may change configuration of your local machine!):

    ansible-playbook -i "localhost," -c local playbook.yml

## Author Information

## Resources

[Guide to the Secure Configuration of Ubuntu 20.04](https://static.open-scap.org/ssg-guides/ssg-ubuntu2004-guide-index.html)

This Ansible remediation role has been generated from the body of security
policies developed by the ComplianceAsCode project. Please see
[https://github.com/complianceascode/content/blob/master/Contributors.md](https://github.com/complianceascode/content/blob/master/Contributors.md)
for an updated list of authors and contributors.
