#!/usr/bin/env bash

printf "\nPort type (t/u): "
read type
printf "\nPort to be scanned: "
read port
printf "\nPath to list (absolute path /dir1/dir2/filename): "
read path

case $type in
        "t") for i in `cat $path`; do echo -e results for $i '\n'; nc -z -v -w5 $i $port; echo -e '\n' ------; done;;
        "u") for i in `cat $path`; do echo -e results for $i '\n'; nmap -sU -v -p $port $i; echo -e '\n' ------; done;;
        *) echo 'Unknown port type, try "t" for TCP and "u" for UDP';;
esac
