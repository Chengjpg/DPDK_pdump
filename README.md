# DPDK_pdump
A tool for capturing packets on DPDK<br/>
Please insatll dpdk-stable-19.11.12 or other version supporting dpdk-pdump<br/>
Install:gcc -o pdump_capture pdump.c -pthread  `pkg-config --cflags --libs libdpdk libpcap`<br/>
Ensure the program open "rte_pdump_init" before using<br/>
Use:./pdump_capture -h<br/>
