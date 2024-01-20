#!/usr/bin/env bash

OUTPUT=$1
CPU_TRIGGER=$2
MEM_TRIGGER=$3
k=1024

while true
do
        DATE=$(date +"[%d/%b/%Y:%k:%M:%S %Z]")
        CPU=$(top -b -n1 | grep -i cpu | head -1 | awk '{print $2}')
        MEMK=$(vmstat -s | head -2 | grep used | awk '{print $1}')
        MEMB=$(awk -v dividend="${MEMK}" -v divisor="${k}" 'BEGIN {printf "%.2f", dividend/divisor; exit(0)}')
        CPU_INT=${CPU%.*}
        MEM_INT=${MEMB%.*}
        if [ $CPU_INT -ge $CPU_TRIGGER ] || [ $MEM_INT -ge $MEM_TRIGGER ]; then
                echo "$DATE: $CPU $MEMB" >> $OUTPUT
        else
                cat /dev/null >> $OUTPUT
        fi
        sleep 1
done
