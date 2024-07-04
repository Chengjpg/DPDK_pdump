# DPDK_pdump
A tool for capturing packets on DPDK
Please insatll dpdk-stable-19.11.12 or other version supporting dpdk-pdump
Install:gcc -o pdump_capture pdump.c -pthread  `pkg-config --cflags --libs libdpdk libpcap`
Ensure the program open "rte_pdump_init" before using
Use:./pdump_capture -h
