#pragma pack(1)

typedef unsigned int   uint32_t;
typedef unsigned short uint16_t;
typedef unsigned char  uint8_t;

struct pcap_header
{
	uint32_t magic;//signature to identify the file 

	uint16_t version_major;//major version ,almost 0x0200
	
	uint16_t version_minor;//minor version ,almost 0x0400
	
	uint32_t thiszone;//gmt to local thiszone correction
	
	uint32_t sigfigs;//accuracy of timestamps
	
	uint32_t snaplen;//the max length of each saved pkt
	
	uint32_t linktype;
};

struct pkt_header
{
	uint32_t sec_time;
	
	uint32_t usec_time;
	
	uint32_t caplen;
	
	uint32_t len;
};

struct ether_header
{
	uint8_t dmac[6];
	
	uint8_t smac[6];
	
	uint8_t eth_typ_len[2];
};

//TCP header
struct ipheader {

	 uint8_t       iplv;//iph_ihl:5, iph_ver:4;

	 uint8_t       iph_tos;

	 uint16_t      iph_len;

	 uint16_t      iph_ident;

	 // unsigned uint8_t      iph_flag;

	 uint16_t      iph_offset;//16bit include flag and offset

	 uint8_t       iph_ttl;

	 uint8_t       iph_protocol;

	 uint16_t      iph_chksum;

	 unsigned int  iph_sourceip;

	 unsigned int  iph_destip;

};

//tcp header

struct tcphdr
{
    unsigned short int source;  
    unsigned short int dest;   
    unsigned int seq;  
    unsigned int ack_seq; 
    unsigned short int tcp_len;
#if 0
    unsigned short int doff:4;
    unsigned short int res1:4;
    unsigned short int res2:2;
    unsigned short int urg:1;
    unsigned short int ack:1;
    unsigned short int psh:1;
    unsigned short int rst:1;
    unsigned short int syn:1;
    unsigned short int fin:1;
#endif
    unsigned short int window;  
    unsigned short int check;  
    unsigned short int urg_prt;  
};

// UDP header's

struct udpheader {

	 uint16_t udph_srcport;

	 uint16_t udph_destport;

	 uint16_t udph_len;

	 uint16_t udph_chksum;
};
#pragma pack()
