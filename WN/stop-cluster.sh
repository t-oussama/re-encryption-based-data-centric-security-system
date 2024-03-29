#!/bin/bash
if [ $# -lt 1 ]
then
    echo "Usage: $0 NUMBER_OF_INSTANCES"
    exit 1
fi

instances_count=$1
for ((i = 0; i < $instances_count; i++))
do
    port=$((8080 + $i))
    ps -eaf |grep main.py\ $port|cut -d ' ' -f 5| xargs kill
done