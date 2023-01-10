rm -r this_sys
mkdir this_sys
mkdir this_sys/hashdeep
mkdir this_sys/misc
mkdir this_sys/installed
for p in /etc /usr/share /usr/lib /home $(echo $PATH | tr ":" " ")
do
getfacl -R $p >> this_sys/acls.txt
done

dpkg-query -f '${binary:Package}\n' -W > this_sys/installed/dpkg.txt
apt list --installed | cut -d/ -f1 > this_sys/installed/apt.txt
snap list | tail -n +2 | awk '{ print $1 }' > this_sys/installed/snap.txt

find /etc/systemd -type f,l | grep ".service" > this_sys/installed/services.txt
find /etc/systemd -type f,l | grep ".timer" > this_sys/misc/timers.txt

##Somehow do transient services and timers


awk "{print $1}" RS='' this_sys/acls.txt | tr "\# " " " | sed s"/^ *//g" | xargs | sed -E s'/file:*/\nfile:/g' > this_sys/temp.txt
mv this_sys/temp.txt this_sys/misc/acls.txt
apt-get install hashdeep
hashdeep -r /etc > ./this_sys/hashdeep/etc.hashdeep
hashdeep -r /usr/share > ./this_sys/hashdeep/usr.share.hashdeep
hashdeep -r /usr/lib > ./this_sys/hashdeep/usr.lib.hashdeep
hashdeep -r /usr > ./this_sys/hashdeep/usr.hashdeep
hashdeep -r /boot > ./this_sys/hashdeep/boot.hashdeep
pip list > hi.txt; cat hi.txt | tail -n +3 | cut -d" " -f1; rm hi.txt > this_sys/installed/pip.txt
lsmod | cut -d" " -f1 > this_sys/kernel-modules.txt

echo $(awk -F: '($3<1000)&&($1!="nobody"){print $1}' /etc/passwd) > results/misc/users.txt

arch=$(dpkg-query -f '${binary:Package}\n' -W | grep zlib1g | cut -d: -f2)
kernel=$(cat this_sys/apt.txt | grep linux-image | head -n 1 | cut -d- -f3,4)

for x in $(find . -type f)
do
sed -i "s/$arch/<arch>/g" $x
sed -i "s/$kernel/<kernel>/g" $x
done
rm -r results
mkdir results
grep -Fxvf files/dpkg.txt this_sys/dpkg.txt > results/dpkg.txt
grep -Fxvf files/apt.txt this_sys/apt.txt > results/apt.txt
grep -Fxvf files/snap.txt this_sys/snap.txt > results/snap.txt
grep -Fxvf files/services.txt this_sys/services.txt > results/services.txt
grep -Fxvf files/timers.txt this_sys/timers.txt > results/timers.txt
grep -Fxvf files/acls.txt this_sys/acls.txt > results/acls.txt
grep -Fxvf files/pip.txt this_sys/pip.txt > results/pip.txt
grep -Fxvf files/kernel-modules.txt this_sys/kernel-modules.txt > results/kernel-modules.txt
grep -Fxvf files/etc.hashdeep this_sys/etc.hashdeep | cut -d, -f4 > results/etc.hashdeep
grep -Fxvf files/usr.hashdeep this_sys/usr.hashdeep | cut -d, -f4 > results/usr.hashdeep
grep -Fxvf files/usr.hashdeep this_sys/usr.share.hashdeep | cut -d, -f4 > results/usr.share.hashdeep
grep -Fxvf files/usr.hashdeep this_sys/usr.lib.hashdeep | cut -d, -f4 > results/usr.lib.hashdeep
grep -Fxvf files/boot.hashdeep this_sys/boot.hashdeep | cut -d, -f4 > results/boot.hashdeep