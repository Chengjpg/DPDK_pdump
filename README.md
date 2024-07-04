# DPDK_pdump
A tool for capturing packets on DPDK
Install:gcc -o pdump_capture pdump.c -pthread  `pkg-config --cflags --libs libdpdk libpcap`
Use:./pdump_capture -h
