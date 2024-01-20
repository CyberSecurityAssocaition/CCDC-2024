#!/usr/bin/env bash

printf "\nEnter host list (absolute path /dir1/dir2/filename): "
read path
printf "\nEnter command: "
read cmnd
printf "\nEnter username: "
read user
printf "\nEnter password: "
read -s password

for i in `cat $path`
do
        printf "\nResults for $i: \n"
        sshpass -p "$password" ssh -o StrictHostKeyChecking=no $user@$i "$cmnd"
        sleep 1
done
