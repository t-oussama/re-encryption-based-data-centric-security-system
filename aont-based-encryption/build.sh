#!/bin/bash
g++ -std=gnu++11 -c -fPIC AontBasedEncryption.cpp -o bin/AontBasedEncryption.o
g++ -std=gnu++11 -shared -Wl,-soname,libAontBasedEncryption.so -o bin/libAontBasedEncryption.so  bin/AontBasedEncryption.o