#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <pcap.h>
#include <rte_eal.h>
#include <rte_mempool.h>
#include <rte_ring.h>
#include <rte_ethdev.h>
#include <rte_pdump.h>

struct conftext {
    pcap_dumper_t *dumper;
    uint16_t port_id;
    uint16_t queue_id;
};
struct conftext conf;
int pcapnum=0;
struct rte_mempool *mp_mbuf;
struct rte_ring *pdump_ring ;
//uint64_t tsc_hz ;

//write to pcap file
void write_to_pcap( struct rte_mbuf *pkt) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    //double timestamp= (double)rte_get_tsc_cycles()/tsc_hz;
    char *pktbuf = rte_pktmbuf_mtod(pkt, char *);    
    struct pcap_pkthdr hdr;
    //hdr.ts.tv_sec = (long) timestamp;
    //hdr.ts.tv_usec = (long)((timestamp- (long) timestamp)*1e6);
    hdr.ts.tv_sec = tv.tv_sec;
    hdr.ts.tv_usec = tv.tv_usec;
    hdr.caplen = rte_pktmbuf_pkt_len(pkt);;
    hdr.len = rte_pktmbuf_pkt_len(pkt);; 
    pcap_dump((u_char*)conf.dumper, &hdr, (const u_char*)pktbuf); 
}

// Function to print usage information
void print_usage(const char *progname) {
    printf("Usage:   %s -n network -q queue -w filename -i ip -p port -l protocol [-h]\n", progname);
    printf("Example: %s -n 0 -q 0 -w 1.pcap -i 127.0.0.1 -p 443 -l tcp \n", progname);
    printf("  -n network    : Specify the port number\n");
    printf("  -q queue      : Specify the queue number\n");
    printf("  -w filename   : Specify the saved file name\n");
    printf("  -i ip         : filter the ip\n");
    printf("  -p port       : filter the port\n");
    printf("  -l protocol   : Filter the protocol\n");   
    printf("  -s p          : Display the port information\n");
    printf("  -s m          : Display the mempool information\n");
    printf("  -h            : Display this help message\n");
}

//show mempool info
void Show_Mempool_Info(void){
    rte_mempool_list_dump(stdout);
}

//show Port info
void Show_Port_Info(void){
    int nb_ports = rte_eth_dev_count_avail();
    if (nb_ports == 0)
        rte_exit(EXIT_FAILURE, "No Ethernet ports - exiting\n");
    uint16_t num_ports = rte_eth_dev_count_avail();
    for (uint16_t port_id = 0; port_id < num_ports; port_id++) {
    struct rte_eth_dev_info dev_info;
    rte_eth_dev_info_get(port_id, &dev_info);
    printf("Port %u:\n", port_id);
    printf("  Driver: %s\n", dev_info.driver_name);
    printf("  Rx queues: %u\n", dev_info.nb_rx_queues);
    printf("  Tx queues: %u\n", dev_info.nb_tx_queues);
    // add other info
    }
}

#define RTE_MEMPOOL_CACHE_SIZE 256
#define NUM_MBUFS 8192
#define MBUF_POOL_NAME "pdump_pool_new"
#define RING_NAME "pdump_ring"



// signal_handler
static void signal_handler(int signum)
{
    if (signum == SIGINT || signum == SIGTERM) {
        //end file
        cap_dump_close(conf.dumper);
        conf.dumper = NULL; 
        rte_pdump_disable(conf.port_id, conf.queue_id,RTE_PDUMP_FLAG_RX);
        //free 
        if (pdump_ring) {
            rte_ring_free(pdump_ring);
        }
        if (mp_mbuf) {
            rte_mempool_free(mp_mbuf);
        }
        // stop pdump  
        printf("PDUMP disabled. %d packets capture finished.\n",pcapnum);
    }
    exit(signum); 
}
 



int main(int argc, char *argv[]) {
    int ret;
    int opt;

    //tsc_hz = rte_get_tsc_hz();
    //default filter
    char *filter_ip = NULL;
    uint16_t filter_port = 0;
    int filter_protocol = 0; // 1 for TCP, 2 for UDP

    //default conf
    conf.port_id=0;
    conf.queue_id=0;
    char* PCAP_FILE= "./rx.pcap";
    conf.dumper= pcap_dump_open(pcap_open_dead(DLT_EN10MB, 1600), PCAP_FILE);

    //signal handler
    //CTRL+C OR KILL PID
    if (signal(SIGINT, signal_handler) == SIG_ERR || signal(SIGTERM, signal_handler) == SIG_ERR) {
        printf("Failed to register SIGINT handler\n");
        return -1;
    }

     //init EAL
    // EAL arguments for secondary process
    char *eal_args[] = {
        argv[0],
        "--proc-type=secondary",
        NULL
    };
    // Initialize the Environment Abstraction Layer (EAL)
    ret = rte_eal_init(2, eal_args);
    if (ret < 0) {
        rte_panic("Cannot init EAL\n");
    }


    // Parse command line options
    while ((opt = getopt(argc, argv, "n:q:w:i:p:l:s:h")) != -1) {
            switch (opt) {
            case 'n':
                 conf.port_id = atoi(optarg);
                break;
            case 'q':
                conf.queue_id = atoi(optarg);
                break;
            case 'w':
                pcap_dump_close(conf.dumper);
                PCAP_FILE = strdup(optarg); // Duplicate string
                conf.dumper= pcap_dump_open(pcap_open_dead(DLT_EN10MB, 1600), PCAP_FILE);
                break;
            case 'i':
                filter_ip = strdup(optarg);
                break;
            case 'p':
                filter_port = atoi(optarg);
                break;
            case 'l':
                if(!strcmp(strdup(optarg),"tcp"))
                    filter_protocol= 1;
                if(!strcmp(strdup(optarg),"udp"))
                    filter_protocol= 2;
                break;
            case 's':
                if(*optarg == 'p')
                    Show_Port_Info();
                if(*optarg == 'm')
                    Show_Mempool_Info();
                exit(EXIT_SUCCESS);
            case 'h':
                print_usage(argv[0]);
                exit(EXIT_SUCCESS);      
            default:
                fprintf(stderr, "Usage: %s -p port -q queue -w name.pcap\n", argv[0]);
                exit(EXIT_FAILURE);
            }
    }

    // init pdump
    ret = rte_pdump_init();
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "Cannot initialize pdump\n");

    // Mempool Lookup
    mp_mbuf = rte_mempool_lookup(MBUF_POOL_NAME);
    if( mp_mbuf == NULL){
        // Mempool Create
        mp_mbuf = rte_pktmbuf_pool_create(MBUF_POOL_NAME,
                    NUM_MBUFS, RTE_MEMPOOL_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE,
                    rte_socket_id());
        if (mp_mbuf == NULL)
            rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

    }
    //printf("Successfully get the pdump mbuf pool '%s'\n", MBUF_POOL_NAME); 
    
    // Ring Lookup
    pdump_ring = rte_ring_lookup(RING_NAME);
    if (pdump_ring == NULL){
        // Ring Create
        pdump_ring = rte_ring_create(RING_NAME,
                                    8192,
                                    rte_socket_id(),
                                    0);
        if (pdump_ring == NULL) {
            rte_exit(EXIT_FAILURE, "Failed to create ring\n");
        }
    }

    // Start pdump
    ret = rte_pdump_enable(conf.port_id, conf.queue_id,RTE_PDUMP_FLAG_RX,pdump_ring,mp_mbuf,NULL);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "Cannot enable pdump\n");


    printf("PDUMP enabled. Capturing packets...\nAt port %d queue %d\n",conf.port_id,conf.queue_id);
    // write from pdump_ring to pcap_file
    while (1) {
        
        struct rte_mbuf *pkt = NULL;
        if (unlikely(rte_ring_dequeue(pdump_ring, (void **)&pkt) < 0) ){
            continue; // when pdump_ring is empty
        }
    /* faster dequeue
        void *pkt_table[1024];
        int num_dequeued;
        num_dequeued = rte_ring_dequeue_burst(pdump_ring, (void **)pkt_table, 1024);
        if(num_dequeued >0)
        {
            for (unsigned int i = 0; i < num_dequeued; i++) {
            // 处理 pkt_table[i]
            // ...
            }

        }
        else
        {
            break;
        }
    */

    //filter
        struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(pkt, struct rte_ether_hdr *);
        if (eth_hdr->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)) {
            struct rte_ipv4_hdr *ipv4_hdr = (struct rte_ipv4_hdr *)(eth_hdr + 1);
            if(filter_ip){
                if ((ntohl(ipv4_hdr->dst_addr) != rte_cpu_to_be_32(inet_addr(filter_ip))) && 
                    (ntohl(ipv4_hdr->src_addr) != rte_cpu_to_be_32(inet_addr(filter_ip)))) {
                    rte_pktmbuf_free(pkt);
                    continue;
                }
            }
            if (filter_protocol) {
                if ((filter_protocol == 1 && ipv4_hdr->next_proto_id != IPPROTO_TCP) ||
                    (filter_protocol == 2 && ipv4_hdr->next_proto_id != IPPROTO_UDP)) {
                    rte_pktmbuf_free(pkt);
                    continue;
                }
            }
            if (filter_port) {
                if (ipv4_hdr->next_proto_id == IPPROTO_TCP) {
                    struct rte_tcp_hdr *tcp_hdr = (struct rte_tcp_hdr *)(ipv4_hdr + 1);
                    if (tcp_hdr->dst_port != rte_cpu_to_be_16(filter_port) && tcp_hdr->src_port != rte_cpu_to_be_16(filter_port)) {
                        rte_pktmbuf_free(pkt);
                        continue;
                    }
                } else if (ipv4_hdr->next_proto_id == IPPROTO_UDP) {
                    struct rte_udp_hdr *udp_hdr = (struct rte_udp_hdr *)(ipv4_hdr + 1);
                    if (udp_hdr->dst_port != rte_cpu_to_be_16(filter_port) && udp_hdr->src_port != rte_cpu_to_be_16(filter_port)) {
                        rte_pktmbuf_free(pkt);
                        continue;
                    }
                }
            }
        }
        write_to_pcap(pkt);
        pcapnum++;
        // free rte_mbuf
        rte_pktmbuf_free(pkt);
    }
    //end program
    pcap_dump_close(conf.dumper);
    conf.dumper = NULL; 
    // stop pdump  
    rte_pdump_disable(conf.port_id, conf.queue_id,RTE_PDUMP_FLAG_RX);
    //free 
    if (pdump_ring) {
        rte_ring_free(pdump_ring);
    }
    if (mp_mbuf) {
        rte_mempool_free(mp_mbuf);
    }
    //rte_ring_reset(pdump_ring);
    //rte_mempool_reset(mp_mbuf);
    printf("PDUMP disabled. %d packets capture finished.\n",pcapnum);

    return 0;
}