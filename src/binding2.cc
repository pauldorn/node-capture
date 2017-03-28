#include <pcap/pcap.h>
#include <stdio.h>
#include <queue>
#include <\Program Files\libuv\include\uv.h>

pcap_t *p;
uv_async_t  async;
int ct = 0;

void error(va_list arg) {
    printf("%s", arg);
    exit(1);
}

void on_timeout( uv_timer_t* handle) {
    printf("Tick\n");
}

void EmitPacket(u_char* pcap_handle,
    const struct pcap_pkthdr* pkt_hdr,
    const u_char* pkt_data) {
    printf("Packet output here: %d.\n", ct++);            
}

void cb_packets( uv_async_t* handle) {
    
    pcap_t *p_handle = (pcap_t*) handle->data;
    int packet_count ;
    do {
        packet_count = pcap_dispatch(p_handle,
                                     -1,
                                     EmitPacket,
                                     (u_char*)handle);
      } while (packet_count > 0 );
}

void onPacket( void* data, BOOLEAN didTimeout) {
    uv_async_t* async = (uv_async_t*)data;
    uv_async_send(async);
}

int main ( int argc, char* argv[]) {

    HANDLE wait;
    int buflen = 65535;
    char errbuf[PCAP_ERRBUF_SIZE];    
    char* filter = (argc == 3)?argv[2]:NULL;
    struct bpf_program fp;
    bpf_u_int32 mask;
    bpf_u_int32 net;

    if (pcap_lookupnet((char*)argv[1],
            &net,
            &mask,
            errbuf) == -1) {
        net = 0;
        mask = 0;
        fprintf(stderr, "Warning: %s - This may not actually work\n", errbuf);
    }

    p = pcap_create(argv[1], errbuf);

    if(p == NULL ) {
        error("Error opening pcap handle\n");
    }
    
    if(pcap_set_snaplen(p, 65535)) {
        error(pcap_geterr(p));
    }
    
    if(pcap_set_promisc(p, 1)) {
        error(pcap_geterr(p));
    }
    
    if(pcap_set_buffer_size(p, 10 * 1024 * 1024)) {
        error(pcap_geterr(p));
    }
    
    if(pcap_set_timeout(p, 1000)) {
        error(pcap_geterr(p));
    }
    
    if( pcap_activate(p) ) {
        error(pcap_geterr(p));
    }
    
    if( pcap_setmintocopy(p, 0)) {
        error(pcap_geterr(p));
    }
    
    if(pcap_setnonblock(p, 1, errbuf)) {
        error(pcap_geterr(p));
    }
    
    if(filter != NULL) {
        if (pcap_compile(p, &fp, filter, 1, net) == -1)
          error(pcap_geterr(p));

        if (pcap_setfilter(p, &fp) == -1)
          error(pcap_geterr(p));

        pcap_freecode(&fp);
    }

    int link_type = pcap_datalink(p);

    switch (link_type) {
        case DLT_NULL:
            printf("NULL Link type.\n");
            break;
        case DLT_EN10MB: // most wifi interfaces pretend to be "ethernet"
            printf("Ethernet Link type.\n");
            break;
        case DLT_IEEE802_11_RADIO: // 802.11 "monitor mode"
            printf("802.11 Radio Link type.\n");
            break;
        case DLT_LINUX_SLL: // "Linux cooked-mode capture"
            printf("Linux Cooked Mode Link type.\n");
            break;
        case DLT_RAW: // "raw IP"
            printf("Raw IP Link type.\n");
            break;
        default:
            printf("Unknown Link type.\n");
            break;
    }   

    async.data = p;
    
    uv_async_init(uv_default_loop(), &async, cb_packets);

    int r = RegisterWaitForSingleObject(&wait, 
                pcap_getevent(p), 
                onPacket, 
                &async, 
                INFINITE, 
                WT_EXECUTEINWAITTHREAD);
   
    if(!r) {
        printf("Error: %s\n", pcap_geterr(p));
    }


    uv_timer_t timer;   
    uv_loop_t *loop = uv_default_loop();
    
    uv_timer_init(loop, &timer);
    
    uv_timer_start(&timer, on_timeout, 1000, 1000);
    
    uv_run(loop, UV_RUN_DEFAULT);
   
}