#!/bin/bash

# for blockSize in '32' '512' '1024'
for blockSize in '512'
do
    echo "Cleanup all python3.9 processes"
    pkill -f python3.9

    echo "Running with block size $blockSize"
    rm -r "../Client/logs/$blockSize" 2>/dev/null
    mkdir ../Client/logs/$blockSize 2>/dev/null
    python3 setup.py $blockSize >/dev/null
    
    cwd=`pwd`
    cd ../TA
    python3.9 ./main.py $cwd/config.yaml | xargs -I {} echo '<TA>:: ' {} &
    sleep 1
    
    cd ../WN
    python3.9 ./main.py ./cluster-configs/node1.yaml | xargs -I {} echo '<WN1>:: ' {} &
    python3.9 ./main.py ./cluster-configs/node2.yaml | xargs -I {} echo '<WN2>:: ' {} &
    sleep 1

    cd ../Client
    python3.9 ./PerformanceTest.py $blockSize

    echo "Cleanup all python3.9 processes"
    pkill -f python3.9
    cd ../Benchmarking
    ./cleanup.sh 2>/dev/null
    echo -e "---------------------------------------------------------------\n\n"
done 