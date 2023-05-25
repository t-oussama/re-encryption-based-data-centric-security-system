#!/bin/bash

blockSizes=(32 512 1024 2048 4096 5120 8192 9216 19456 52224 103424 513024 1048576) #10485760 104857600 524288000)

for blockSize in ${blockSizes[@]}
do
    python3 BlockSizeBenchmark.py $blockSize
done