#!/usr/bin/env bash

FILE=$1
SERVER=$2
for i in `cat $FILE`; do nslookup $i $SERVER | tail -3; done
