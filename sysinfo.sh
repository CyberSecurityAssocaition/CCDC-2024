#!/usr/bin/env bash

##Vitals##

HOST=$(uname -n)
UPTIME=$(w | grep up | awk '{for (i=1;i<=NF;i++) if ($i == "up") {print $(i+1)};}')
UPTIME_DAY=$(w | grep up | awk '{for (i=1;i<=NF;i++) if ($i == "up") {print $(i+2)};}' | sed 's/.$//')
ADDR=$(ip r l | grep src | awk '{for (i=1;i<=NF;i++) if ($i == "src") {print $(i+1)};}')
CPU_CORES=$(lscpu | egrep -i "model name|socket")
TOTAL_MEM=$(vmstat -s | grep "total memory")
USED_MEM=$(vmstat -s | head -2 | grep used | awk '{print $1}')
USED_CPU=$(vmstat 1 2 -a | tail -1 | awk '{print $13+$14}')
OS=$(lsb_release -a | tail -4)
KERNEL=$(cat /proc/version)
DMI=$(dmidecode -t bios -t chassis -t baseboard -t system | egrep "BIOS Information|Vendor:|System Information|Manufacturer:|Product Name:|UUID:|Chassis Information|Manufacturer:|Asset Tag:|Base Board Information|Manufacturer:")

##Disk and FS##

DISKS=$(fdisk -l | grep "Disk /dev" | grep -v mapper)
function disk_health() {
        fdisk -l | grep "Disk /dev*" | grep -v mapper | awk '{print $2}' | sed 's/.$//' >> /tmp/disks_out.txt
        for i in `cat /tmp/disks_out.txt`; do smartctl -a $i; sleep 1; wait; done
        rm -f /tmp/disks_out.txt
}
LOC_FS=$(df -lT -xtmpfs -xdevtmpfs -xcifs | awk -v OFS='\t' '{print $7,$2,$6}')

##Link and DNS##

DEF_GW=$(ip r l | grep via | awk '{for (i=1;i<=NF;i++) if ($i == "via") {print $(i+1)};}')
DNS_SRV1=$(grep "^[^#;]" /etc/resolv.conf | grep name | head -1 | awk '{print $2}')
DNS_SRV2=$(grep "^[^#;]" /etc/resolv.conf | grep name | tail -1 | awk '{print $2}')
function link_detect () {
        ping -c 2 "$DEF_GW" > /dev/null
        if [ $? -eq 0 ]; then
                printf "\nGateway is reachable."
        else
                printf "\nGateway is unreachable."
        fi
}
function dns_check () {
        rev_lookup=$(nslookup $ADDR $DNS_SRV1 | grep "name" | grep -v "nameserver" | awk '{print $4}' | sed 's/.$//')
        for_lookup=$(nslookup $HOST $DNS_SRV2 | tail -2 | grep -i addr | awk '{print $2}')
        if [ "$rev_lookup" == "$HOST" ] && [ "$for_lookup" == "$ADDR" ]
        then
                printf "\nForward and Reverse lookups are good!"
        else
                printf "\nDNS mismatch. Please investigate."
        fi
}

##Process##

HIGH_CPU=$(ps -eo pcpu,pid,user,args | sort -k 1 -r | head -6)
HIGH_MEM=$(ps -eo %mem,pid,user,args | sort -k 1 -r | head -6)

##Display info##

printf "\nHostname: $HOST \nUptime: $UPTIME $UPTIME_DAY \nIP: $ADDR \nCPU info: --↓ \n$CPU_CORES \nTotal memory: $TOTAL_MEM \nUsed memory: $USED_MEM K \nCurrent CPU usage: $USED_CPU%% \nOS: --↓ \n$OS \nKernel version: $KERNEL"
printf "\nHardware info: --↓ \n$DMI"

printf "\nPhysical disks: --↓ \n$DISKS \n"
printf '%s\n' "${LOC_FS}"
disk_health

printf "\nTop 5 CPU intensive processes: --↓ \n"
printf '%s\n' "$HIGH_CPU \n"

printf "\nTop 5 memory intensive processes: --↓ \n"
printf '%s\n' "$HIGH_MEM \n"

link_detect
dns_check

echo -e "\nEnd Of Sysinfo"
