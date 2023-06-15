#!/bin/bash

for blockSize in '32' '512' '1024' '2048' '4096' '8192'
do
    echo "Cleanup all python3.9 processes"
    pkill -f python3.9

    echo "Running with block size $blockSize"
    rm -r "../Client/logs/$blockSize"
    mkdir ../Client/logs/$blockSize
    python3 setup.py $blockSize >/dev/null
    
    cwd=`pwd`
    cd ../TA
    python3.9 ./main.py $cwd/config.yaml >/dev/null &
    sleep 3
    
    cd ../WN
    python3.9 ./main.py ./cluster-configs/node1.yaml >/dev/null &
    python3.9 ./main.py ./cluster-configs/node2.yaml >/dev/null &
    sleep 2

    cd ../Client
    python3.9 ./PerformanceTest.py $blockSize >/dev/null

    echo "Cleanup all python3.9 processes"
    pkill -f python3.9
done 