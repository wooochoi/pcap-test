#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <libnet.h>

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

		struct libnet_ethernet_hdr* ethernet;
		struct libnet_ipv4_hdr* ipv4;
		struct libnet_tcp_hdr* tcp;

		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}

		ethernet = (struct libnet_ethernet_hdr*)packet;
		ipv4 = (struct libnet_ipv4_hdr*)(packet + 14);
		__uint8_t ihl = ipv4->ip_hl; 


		tcp = (struct libnet_tcp_hdr*)(packet + 14 + ihl*4);
		__uint8_t thl = tcp->th_off;
		u_char* data;

		data = (u_char*)(packet + 14 + ihl*4 + thl*4);


		if (ntohs(ethernet->ether_type) != 0x0800) {
			continue;
		}

		if (ipv4->ip_p != 0x06) {
			continue;
		}


		printf("Ethernet Header's src mac: %x:%x:%x:%x:%x:%x\n", ethernet->ether_shost[0], ethernet->ether_shost[1], ethernet->ether_shost[2], ethernet->ether_shost[3], ethernet->ether_shost[4], ethernet->ether_shost[5]);
		printf("Ethernet Header's dst mac: %x:%x:%x:%x:%x:%x\n", ethernet->ether_dhost[0], ethernet->ether_dhost[1], ethernet->ether_dhost[2], ethernet->ether_dhost[3], ethernet->ether_dhost[4], ethernet->ether_dhost[5]);

		char *str;
		str = inet_ntoa(ipv4->ip_src);
		printf("IP Header's src ip: %s\n", str);

		str = inet_ntoa(ipv4->ip_dst);
		printf("IP Header's dst ip: %s\n", str);

		printf("TCP Header's src port: %u\n", ntohs(tcp->th_sport));
		printf("TCP Header's dst port: %u\n", ntohs(tcp->th_dport));

		printf("Payload's hexadecimal value: %x %x %x %x %x %x %x %x\n", *data, *(data+1), *(data+2), *(data+3), *(data+4), *(data+5), *(data+6), *(data+7));
	}

	pcap_close(pcap);
}
