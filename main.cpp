#include <cstdio>
#include <stdio.h>
#include <pcap.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <string.h>
#include "Ethernet-structure.h"
#define SIZE_ETHERNET 14 
void usage() {
    printf("syntax : tcp-block <interface> <pattern>\n");
    printf("sample : tcp-block wlan0 \"Host: test.gilgil.net\"\n");
}

pcap_t* handle;
u_int8_t fw[9999]={0,};
u_int8_t bk[9999]={0,};
u_int8_t mymac[6];
const char* block="blocked!!!";

typedef struct tcp_packet
{
    struct sniff_ethernet eth_hdr;
    struct sniff_ip ip_hdr;
    struct sniff_tcp tcp_hdr;
}tcp_packet;


int rst_fw(u_int8_t* packet,unsigned int length){
    struct sniff_ethernet* eth_hdr=(struct sniff_ethernet *)packet;
    struct sniff_ip* ip_hdr = (struct sniff_ip *)(packet +SIZE_ETHERNET);
    struct sniff_tcp* tcp_hdr=(struct sniff_tcp *)(packet+SIZE_ETHERNET+IP_HL(ip_hdr)*4);

    for(int i=0;i<6;i++){
        eth_hdr->ether_shost[i]=mymac[i];
    }
    ip_hdr->ip_len=htons(IP_HL(ip_hdr)*4+TH_OFF(tcp_hdr)*4);
    tcp_hdr->th_seq=htonl(ntohl(tcp_hdr->th_seq)+TH_OFF(tcp_hdr)*4);
    tcp_hdr->th_flags|=TH_RST;

    u_int32_t checksum=0;  
    ip_hdr->ip_sum =0;
    u_int16_t* ip_h=(u_int16_t*)ip_hdr;
    for(int i=0;i<(IP_HL(ip_hdr)*4)/2;i++){
        checksum+=ip_h[i];
    }
    checksum=(checksum>>16)+(checksum&0xffff);
    checksum=(checksum>>16)+(checksum&0xffff);
    checksum= ~checksum;
    ip_hdr->ip_sum =(u_int16_t)checksum;   

    checksum=0;
    tcp_hdr->th_sum =0;
    u_int16_t* tcp_h=(u_int16_t*)tcp_hdr;
    for(int i=0;i<(TH_OFF(tcp_hdr)*4)/2;i++){
        checksum+=tcp_h[i];
    }
    checksum+=(ip_hdr->ip_src>>16)+(ip_hdr->ip_src&0xffff);
    checksum+=(ip_hdr->ip_dst>>16)+(ip_hdr->ip_dst&0xffff);
    checksum+=ip_hdr->ip_p;
    checksum+=TH_OFF(tcp_hdr)*4;
    checksum=(checksum>>16)+(checksum&0xffff);
    checksum=(checksum>>16)+(checksum&0xffff);
    checksum= ~checksum;
    tcp_hdr->th_sum =(u_int16_t)checksum;   

    int len=  SIZE_ETHERNET+IP_HL(ip_hdr)*4+TH_OFF(tcp_hdr)*4;
    
	int res1 = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), len);
	if (res1 != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res1, pcap_geterr(handle));
	}
    return 0;
}

int fin_bk(u_int8_t* packet,unsigned int length){
 
    struct sniff_ethernet* eth_hdr=(struct sniff_ethernet *)packet;
    struct sniff_ip* ip_hdr = (struct sniff_ip *)(packet +SIZE_ETHERNET);
    struct sniff_tcp* tcp_hdr=(struct sniff_tcp *)(packet+SIZE_ETHERNET+IP_HL(ip_hdr)*4);
    strncpy((char*)tcp_hdr+TH_OFF(tcp_hdr)*4,block,11);

    for(int i=0;i<6;i++){
        eth_hdr->ether_dhost[i]=eth_hdr->ether_shost[i];
    }
    for(int i=0;i<6;i++){
        eth_hdr->ether_shost[i]=mymac[i];
    }

    ip_hdr->ip_len=htons(IP_HL(ip_hdr)*4+TH_OFF(tcp_hdr)*4+11);
    ip_hdr->ip_ttl=0x80;
    u_int32_t src_ip=ip_hdr->ip_src;
    u_int32_t dst_ip=ip_hdr->ip_dst;
    ip_hdr->ip_dst=src_ip;
    ip_hdr->ip_src=dst_ip;

    u_int16_t dport=tcp_hdr->th_dport;
    u_int16_t sport=tcp_hdr->th_sport; 
    tcp_hdr->th_sport=dport;
    tcp_hdr->th_dport=sport;   
    tcp_hdr->th_seq=tcp_hdr->th_ack;
    tcp_hdr->th_ack=htonl(ntohl(tcp_hdr->th_seq)+TH_OFF(tcp_hdr)*4);
    tcp_hdr->th_flags|=TH_FIN;

    u_int32_t checksum=0;  
    ip_hdr->ip_sum =0;
    u_int16_t* ip_h=(u_int16_t*)ip_hdr;
    for(int i=0;i<(IP_HL(ip_hdr)*4)/2;i++){
        checksum+=ip_h[i];
    }
    checksum=(checksum>>16)+(checksum&0xffff);
    checksum=(checksum>>16)+(checksum&0xffff);
    checksum= ~checksum;
    ip_hdr->ip_sum =(u_int16_t)checksum;   

    checksum=0;
    tcp_hdr->th_sum =0;
    u_int16_t* tcp_h=(u_int16_t*)tcp_hdr;
    for(int i=0;i<(TH_OFF(tcp_hdr)*4+12)/2;i++){
        checksum+=tcp_h[i];
    }
    checksum+=(ip_hdr->ip_src>>16)+(ip_hdr->ip_src&0xffff);
    checksum+=(ip_hdr->ip_dst>>16)+(ip_hdr->ip_dst&0xffff);
    checksum+=ip_hdr->ip_p;
    checksum+=TH_OFF(tcp_hdr)*4;
    checksum=(checksum>>16)+(checksum&0xffff);
    checksum=(checksum>>16)+(checksum&0xffff);
    checksum= ~checksum;
    tcp_hdr->th_sum =(u_int16_t)checksum;   

    int len=  SIZE_ETHERNET+IP_HL(ip_hdr)*4+TH_OFF(tcp_hdr)*4+8;
    
	int res1 = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&fw), len);
	if (res1 != 0) {
			fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res1, pcap_geterr(handle));
	}
    return 0;
}

int find_pattern(const u_char* packet, unsigned int length, char* pattern){	
    struct sniff_ethernet* eth_hdr=(struct sniff_ethernet *)packet;
    if(length<SIZE_ETHERNET){
        return 0;
    }
	struct sniff_ip* ip_hdr = (struct sniff_ip *)(packet +SIZE_ETHERNET);
    if(ip_hdr->ip_p != 0x06){
        return 0;
    }
    if(length<SIZE_ETHERNET+IP_HL(ip_hdr)*4){
        return 0;
    }
	struct sniff_tcp* tcp_hdr=(struct sniff_tcp *)(packet+SIZE_ETHERNET+IP_HL(ip_hdr)*4);
    u_int8_t* data=(u_int8_t*)tcp_hdr+TH_OFF(tcp_hdr)*4;
    int data_len=ntohs(ip_hdr->ip_len) - IP_HL(ip_hdr)*4 - TH_OFF(tcp_hdr)*4;
    if(data_len<strlen(pattern)){
        return 0;
    }
    for(int i=0;i<data_len-strlen(pattern);i++){
        if(!strncmp((char*)data+i,pattern,strlen(pattern)))
            {
                memcpy(fw,packet,9999);
                rst_fw(fw,length);
                memcpy(bk,packet,9999);
                fin_bk(bk,length);
                break;
            }
    }
    return 0;
}


int main(int argc, char*argv[]){
        if (argc != 3) {
        usage();
        return -1;
    }

    char* dev = argv[1];
    char* pattern= argv[2];
    char errbuf[PCAP_ERRBUF_SIZE];
    handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "pcap_open_live(%s) return nullptr - %s\n", dev, errbuf);
        return -1;
    }

	struct ifreq ifrq;
	int soc = socket(AF_INET, SOCK_DGRAM, 0);
	strcpy(ifrq.ifr_name, dev);
	ioctl(soc,SIOCGIFHWADDR, &ifrq);
	for (int i=0; i<6; i++){
		mymac[i] = ifrq.ifr_hwaddr.sa_data[i];
    }



    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }
        find_pattern(packet, header->len,pattern);
    }

    pcap_close(handle);
}