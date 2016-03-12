#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "head.h"


int main()
{
	FILE *fpd,*fps,*fpp;
	uint32_t i = 0,j = 0,count = 0,src_len = 0,tcphdr_data_len = 0;
	char *ins_buff = NULL,*eth_ip_buff = NULL,*tcphdr_data_buff = NULL;
	int src_cur_point = 0,dst_cur_point,file_len = 0;
	struct pcap_header *file_header = (struct pcap_header *)malloc(sizeof(struct pcap_header));
	struct pkt_header *packet_header = (struct pkt_header *)malloc(sizeof(struct pkt_header));

	struct ether_header *eth_data = (struct ether_header *)malloc(sizeof(struct ether_header)); 
	struct ipheader *ip_data = (struct ipheader *)malloc(sizeof(struct ipheader));
	struct tcphdr *tcphdr_data = (struct tcphdr *)malloc(sizeof(struct tcphdr));


	if((fpd = fopen("10.pcap","r+"))==NULL)
	{
		printf("open 10.pcap file failure\n");
		exit(0);
	}
	if((fps = fopen("output.txt","r"))==NULL)
	{
		printf("open output.txt file failure\n");
		exit(0);
	}
	if((fpp = fopen("mod10.pcap","a"))==NULL)
	{
		printf("open mod10.pcap file failure\n");
		exit(0);
	}
	
	//get the len of insert file
	fseek(fps,0,SEEK_END);
	src_len = ftell(fps);
	printf("src_len:%d\n",src_len);
	ins_buff = (char *)malloc(src_len);
	fseek(fps,0,SEEK_SET);
	printf("read_len:%d\n",fread(ins_buff,1,src_len,fps));


	//get the len of src pcap file
	//printf("sizeof(struct pcap_header):%d\n",sizeof(struct pcap_header));
	fseek(fpd,0,SEEK_END);
	file_len = ftell(fpd);
	printf("file_len:%d\n",ftell(fpd));


	printf("*****************pcap file header*************************/\n");
	fseek(fpd,0,SEEK_SET);
	printf("sizeof(pcap_header):%d\n",sizeof(struct pcap_header));
	fread(file_header,1,sizeof(struct pcap_header),fpd);
	src_cur_point += sizeof(struct pcap_header);
	fwrite(file_header,1,sizeof(struct pcap_header),fpp);
	dst_cur_point += sizeof(struct pcap_header);
	
	printf("pcap_header:\nmagic:%#x\n version_major:%#x version_minor:%#x\nthiszone:%#x\nsigfigs:%#x\nsnaplen:%#x\nlinktype:%#x\n",file_header->magic,file_header->version_major,file_header->version_minor,file_header->thiszone,file_header->sigfigs,file_header->snaplen,file_header->linktype);

	printf("*****************end pcap file header**************************/\n\n");

	
	

	while(1)
	{
		if(!(src_cur_point < file_len))
		{
			break;
		}
	printf("*****************packet header data*************************/\n");
	printf("count:%d\n",count++);

	fseek(fpd,src_cur_point,SEEK_SET);	
	printf("src_cur_point:%d\n",src_cur_point);
	fread(packet_header,1,sizeof(struct pkt_header),fpd);
	src_cur_point +=sizeof(struct pkt_header);

	fseek(fpp,dst_cur_point,SEEK_SET);	
	fwrite(packet_header,1,sizeof(struct pkt_header),fpp);
	dst_cur_point +=sizeof(struct pkt_header);


    	fseek(fpd,src_cur_point,SEEK_SET);
	eth_ip_buff = malloc(sizeof(struct ether_header) + sizeof(struct ipheader));
	fread(eth_ip_buff,1,sizeof(struct ether_header) + sizeof(struct ipheader),fpd);
	src_cur_point = src_cur_point + sizeof(struct ether_header) + sizeof(struct ipheader);
	printf("src_cur_point:%d\n",src_cur_point);

	fseek(fpp,dst_cur_point,SEEK_SET);	
	fwrite(eth_ip_buff,1,sizeof(struct ether_header) + sizeof(struct ipheader),fpp);
	dst_cur_point = dst_cur_point + sizeof(struct ether_header) + sizeof(struct ipheader);
	
		
	fseek(fpp,dst_cur_point,SEEK_SET);	
	fwrite(ins_buff,1,src_len,fpp);
	dst_cur_point = dst_cur_point + src_len;

	printf("the space we need\n");


    	fseek(fpd,src_cur_point,SEEK_SET);
	tcphdr_data_len = packet_header->len - sizeof(struct ether_header) - sizeof(struct ipheader);
	tcphdr_data_buff = malloc(tcphdr_data_len);
	fread(tcphdr_data_buff,1,tcphdr_data_len,fpd);
	src_cur_point = src_cur_point + tcphdr_data_len;

	
	fseek(fpp,dst_cur_point,SEEK_SET);	
	fwrite(tcphdr_data_buff,1,tcphdr_data_len,fpp);
	dst_cur_point = dst_cur_point + tcphdr_data_len;

	printf("src_cur_point:%d\n",src_cur_point);

#if 0
	printf("************tcp header data****************/\n");
	fread(tcphdr_data,1,sizeof(struct tcphdr),fpd);
	printf("it is small endian\n");//such as 0xbb01---->0x01bb
	printf("tcp:src port:%#x dst port:%#x\n",tcphdr_data->source,tcphdr_data->dest);
	memset(tcphdr_data,0,sizeof(struct tcphdr));
	printf("tcp:src port:%#x dst port:%#x\n",tcphdr_data->source,tcphdr_data->dest);
	printf("*********end tcp header data****************/\n");
#endif

	printf("pkt_header:\nsec_time:%#x\nusec_time:%#x\ncaplen:%#x\nlen:%#x\n",packet_header->sec_time,packet_header->usec_time,packet_header->caplen,packet_header->len);
	//memset(packet_header,0,sizeof(struct pkt_header));
	printf("****************end packet header data*********************/\n\n");
		
	}

	fclose(fpp);
	fclose(fpd);
	fclose(fps);
	return 0;
}
