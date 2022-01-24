#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <libnet.h>
#include <netinet/in.h>

void printEthernetHeader(const struct libnet_ethernet_hdr* ethr) {
    printf("1. Ethernet\n");
    printf("-src MAC = ");
    for(int i=0; i < 6; i++) {
        printf("%02x",ethr->ether_shost[i]);
        if(i != 5) printf(":");
    }
    printf("\n-dst MAC = ");
    for(int i=0; i < 6; i++) {
        printf("%02x",ethr->ether_dhost[i]);
        if(i != 5) printf(":");
    }
    printf("\n");
}

void printIPHeader(const struct libnet_ipv4_hdr* iph) {
    printf("2. IP Header\n");
    printf("-src IP = %s\n",inet_ntoa(iph->ip_src));
    printf("-dst IP = %s\n",inet_ntoa(iph->ip_dst));
}

void printTCPHeader(const struct libnet_tcp_hdr* tcph) {
    printf("3. TCP Header\n");
    printf("-src prot = %d\n",ntohs(tcph->th_sport));
    printf("-dst port = %d\n",ntohs(tcph->th_dport));
}

void printData(const u_char* data, uint32_t hdr_size, uint32_t total_len) {
    printf("4. Payload\n");
    if(total_len <= hdr_size) {
        printf("- no payload\n");
    }else{
        printf("-data = ");

        int count = total_len - hdr_size;
        if (count > 8 ) count = 8;
        for(int i = 0; i < count; i++){
            printf("%02x ",data[i]);
        }
        printf("\n");
    }

}

void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

typedef struct {
	char* dev_;
} Param;

Param param  = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	while (true) {
		struct pcap_pkthdr* header;
        struct libnet_ethernet_hdr* ethrHdr;
        struct libnet_ipv4_hdr* IPHdr;
        struct libnet_tcp_hdr* TCPHdr;
        u_char* data_offset;
        uint32_t hdr_len;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
        ethrHdr = (struct libnet_ethernet_hdr*) packet;

        if (ntohs(ethrHdr->ether_type) != ETHERTYPE_IP) continue;
        IPHdr = (struct libnet_ipv4_hdr*) (packet + sizeof(struct libnet_ethernet_hdr));
        

        if (IPHdr->ip_p == 6) continue;
        TCPHdr = (struct libnet_tcp_hdr*) (packet + sizeof(struct libnet_ethernet_hdr) + (IPHdr->ip_hl)*4);
       
        hdr_len = sizeof(struct libnet_ethernet_hdr) + (IPHdr->ip_hl)*4 + (TCPHdr->th_off)*4;
        data_offset = (u_char *) (packet + hdr_len);

        printEthernetHeader(ethrHdr);
        printIPHeader(IPHdr);
        printTCPHeader(TCPHdr);
        printData(data_offset, hdr_len, header->caplen);
        printf("\n");
        //printf("%u bytes captured\n", header->caplen);
	}

	pcap_close(pcap);
}
