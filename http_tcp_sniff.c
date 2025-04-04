#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
#include "myheader.h"

void got_packet(u_char *args, const struct pcap_pkthdr *header,
                              const u_char *packet)
{
  //MAC 주소 출력 구문 및 이더넷 헤더 구조체 선언
  struct ethheader *eth = (struct ethheader *)packet;
  printf("Ethernet Header: \n");
  printf("  src mac : ");
  for(int i=0; i<=5; i++)
	  printf("%02x ",eth->ether_shost[i]);
  printf("\n  dst mac : ");
  for(int i=0; i<=5; i++)
	  printf("%02x ",eth->ether_dhost[i]);
 //ip 주소 출력 구문 및 ip헤더 구조체 선언,http만
  if (ntohs(eth->ether_type) == 0x0800) {
    struct ipheader * ip = (struct ipheader *)
                           (packet + sizeof(struct ethheader)); 
    //tcp 구조체 선언을 위해 가변적인 ip헤더의 길이를 알아냄.
    int ip_header_len = ip->iph_ihl * 4;
    printf("\nIP Header : ");
    printf("\n  src ip : %s", inet_ntoa(ip->iph_sourceip));
    printf("\n  dst ip : %s", inet_ntoa(ip->iph_destip));

     // TCP 구조체 선언 및 포트 주소 출력
     if(ip->iph_protocol == IPPROTO_TCP){
  	   struct tcpheader *tcp = (struct tcpheader *)
		   		   (packet + sizeof(struct ethheader) + ip_header_len);
	// tcp 헤더 길이, http 메시지 추출을 위한 작업
	int tcp_header_len = TH_OFF(tcp) * 4;
	printf("\nTCP Header : ");				   
	printf("\n  src port : %d", tcp->tcp_sport);
	printf("\n  dst port : %d",tcp->tcp_dport);

	//http 메시지 추출
	const u_char *payload = packet + sizeof(struct ethheader) + ip_header_len + tcp_header_len;
	int payload_len = header -> caplen -(sizeof(struct ethheader) + ip_header_len + tcp_header_len);
	if(payload_len) {
		printf("\nMESSAGE : \n");
		int avg_len = (payload_len > 150) ? 150 : payload_len;
		printf("\n%.*s",avg_len,payload);
		if(payload_len>150)
			printf(".....too long :( \n");
	}//http 출력 구문 괄호


    } // tcp 구조체 괄호
  } // ip 구조체 괄호
  printf("\n==========================\n");
} //got_packet 괄호

int main()
{
  pcap_t *handle;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program fp;
  char filter_exp[] = "tcp port 80"; //http, tcp를 원하므로 필터조건을 변경
  bpf_u_int32 net;

  // Step 1: Open live pcap session on NIC with name enp0s3
  handle = pcap_open_live("enp0s3", BUFSIZ, 1, 1000, errbuf); //가상머신의 NIC 번호를 입력

  // Step 2: Compile filter_exp into BPF psuedo-code
  pcap_compile(handle, &fp, filter_exp, 0, net);
  if (pcap_setfilter(handle, &fp) !=0) {
      pcap_perror(handle, "Error:");
      exit(EXIT_FAILURE);
  }

  // Step 3: Capture packets
  pcap_loop(handle, -1, got_packet, NULL);

  pcap_close(handle);   //Close the handle
  return 0;
}


