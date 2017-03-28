#include <pcap/pcap.h>
#include <stdio.h>
#include <queue>
#include <\Program Files\libuv\include\uv.h>

typedef char *cptr;
pcap_t *p;
uv_rwlock_t queueLock;
uv_async_t  async;

void error(va_list arg) {
    printf("%s", arg);
    exit(1);
}

class pkt {
    public:
    int len;
    u_char *payload;

    pkt(int size, u_char * data) {
        len = size;
        payload = new u_char[len]();
        std::memcpy(payload, data, len);
    };
    ~pkt() {
        free(payload);
    }
};
std::queue<pkt*> q;

void proc_read_packets(void* data) {
    pcap_pkthdr *pkt_header;
    const u_char *packetData ;
    // union {
    //     u_char lengthbin[sizeof(int)];
    //     int length;
    //     };
    int ret;
    
    
    for(;;) {

        ret = pcap_next_ex(p, &pkt_header,  &packetData);
        switch(ret) {
            case 1: 
            uv_rwlock_wrlock(&queueLock);
            q.push(new pkt(pkt_header->len, (u_char *) packetData));
            uv_rwlock_wrunlock(&queueLock);
            uv_async_send(&async); 
            break;
            case 0: printf("Timeout reached\n"); break;
            case -1: printf("Error: %s\n", pcap_geterr(p)); break;
            case -2: printf("EOF reached\n");
        }
    }
}

void on_timeout( uv_timer_t* handle) {
    printf("Tick\n");
}

void emit_packet( uv_async_t* ignoreme) {
    pkt* p;
    u_char header[] = { 255, 255, 255, 255, 255 };
    u_char match[] = { 255, 255};

    uv_rwlock_wrlock(&queueLock);
    while(q.size()) {
        p = (pkt *) q.front();
        q.pop();
        header[3] = (p->len & 0xffff) >> 8;
        header[4] = (p->len & 0xff);
        printf("%d %d %d %d\n", header[1],header[2],header[3],header[4]); 
        if( std::string::npos != std::basic_string<BYTE>(p->payload).find(match, 0, 2)) {
            // printf("Double FF found in packet.\n");
        }
        //fwrite(p->payload, p->len, 1, stdout);
        delete p;
    }
    uv_rwlock_wrunlock(&queueLock);
    
}

int main ( int argc, char* argv[]) {
    
    int buflen = 65535;
    char errbuf[PCAP_ERRBUF_SIZE];    
    char* filter = (argc == 3)?argv[2]:NULL;
    struct bpf_program fp;
    bpf_u_int32 mask;
    bpf_u_int32 net;
    uv_thread_t proc_r_p;
    int t = 0;

    if (pcap_lookupnet((char*)argv[1],
            &net,
            &mask,
            errbuf) == -1) {
        net = 0;
        mask = 0;
        fprintf(stderr, "Warning: %s - This may not actually work\n", errbuf);
    }

    p = pcap_open_live(argv[1], 65535, 1, 0, errbuf);

    if(p == NULL ) {
        error("Error opening pcap handle\n");
    }
    
    // if (pcap_setnonblock(p, 1, errbuf) == -1)
    // {
    //     error(errbuf);
    // }

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

    uv_thread_create(&proc_r_p, proc_read_packets, &t);
   
   

    uv_timer_t timer;   
    uv_loop_t *loop = uv_default_loop();
    uv_rwlock_init(&queueLock);
    uv_async_init(loop, &async, emit_packet);

    uv_timer_init(loop, &timer);
    
    uv_timer_start(&timer, on_timeout, 1000, 1000);
    
    uv_run(loop, UV_RUN_DEFAULT);
    // Not waiting for the thread to end.
    // uv_thread_join(&proc_r_p); 
}