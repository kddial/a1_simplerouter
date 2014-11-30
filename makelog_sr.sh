#!/bin/bash
# run this script when making files that are in the 'future'
find -exec touch \{\} \;
make clean
make
./sr -l log2.pcap
