#!/bin/bash
# Script to harden ssh on ubuntu/debian server
# follow on my blog http://www.coderew.com/hardening_ssh_on_remote_ubuntu_debian_server/ 
# checkout the repo for more scripts https://github.com/nvnmo/handy-scripts

read -p "Enter your server IP:" serverIP # prompt for server IP
read -p "Enter your username(requires root privileges):" username # prompt for username
printf "\nChanging the default SSH port is one of the easiest\n things you can do to help harden you servers security. \nIt will protect you from robots that are programmed \nto scan for port 22 openings, and commence \ntheir attack."
printf "\n"
read -p "Do you want to change default SSH port?[Y/n]" -n 1 portChange
printf "\n"
portNum=0
if [[ $portChange =~ ^[Yy]$ ]];then
  printf "Choose an available port.The port number does not \nreally matter as long as you do no choose something that \nis already in use and falls within the \nport number range."
  printf "\n"
  read -p "Port Number:" portNum # a port num to change
  printf "\n"
fi
printf "\n"
read -p "Do you want to disable root login?[Y/n]" -n 1 rootLogin;printf "\n"
read -p "Do you want to change protocol version to 2?[Y/n]" -n 1 protocolChange;printf "\n"
read -p "Do you want to enable privilege seperation?[Y/n]" -n 1 privilegeSep;printf "\n"
read -p "Do you want to disable empty passwords?[Y/n]" -n 1 emptyPass;printf "\n"
read -p "Do you want to disable X11 forwarding?[Y/n]" -n 1 x11Forwarding;printf "\n"
read -p "Do you want to enable TCPKeepAlive to avoid zombies?[Y/n]" -n 1 zombies;printf "\n"


echo "cat /etc/ssh/sshd_config > /etc/ssh/sshd_config.bak" > .local_script_$0

if [[ $portChange =~ ^[Yy]$ ]];then
  echo "sed \"s/.*Port.*/Port $portNum/\" /etc/ssh/sshd_config > temp" >> .local_script_$0
  echo "cp temp /etc/ssh/sshd_config" >> .local_script_$0
fi
if [[ $rootLogin =~ ^[Yy]$ ]];then
  echo "sed '0,/^.*PermitRootLogin.*$/s//PermitRootLogin no/' /etc/ssh/sshd_config" >> .local_script_$0

fi
if [[ $protocolChange =~ ^[Yy]$ ]];then
  echo "sed -i \"s/^.*Protocol.*$/Protocol 2/\" /etc/ssh/sshd_config" >> .local_script_$0

fi
if [[ $privilegeSep =~ ^[Yy]$ ]];then
  echo "sed -i \"s/^.*UsePrivilegeSeparation.*$/UsePrivilegeSeparation yes/\" /etc/ssh/sshd_config" >> .local_script_$0

fi
if [[ $emptyPass =~ ^[Yy]$ ]];then
  echo "sed -i \"s/^.*PermitEmptyPasswords.*$/PermitEmptyPasswords no/\" /etc/ssh/sshd_config" >> .local_script_$0

fi
if [[ $x11Forwarding =~ ^[Yy]$ ]];then
  echo "sed -i \"s/^.*X11Forwarding.*$/X11Forwarding no/\" /etc/ssh/sshd_config" >> .local_script_$0

fi
if [[ $zombies =~ ^[Yy]$ ]];then
  echo "sed -i \"s/^.*TCPKeepAlive.*$/TCPKeepAlive yes/\" /etc/ssh/sshd_config" >> .local_script_$0

fi

MYSCRIPT=`base64 -w0 .local_script_$0`
ssh -t $username@$serverIP "echo $MYSCRIPT | base64 -d | sudo bash"
rm .local_script_$0
echo "Success"
exit
