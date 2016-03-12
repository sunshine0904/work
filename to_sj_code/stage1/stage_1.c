#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "head.h"
#include "aes_lib.h"

int main()
{
	FILE *fp,*fpd;
	char buffer[25];
	struct m_ip temp[num_ip];
	int line = 0,i = 0,j = 0;
	struct encrypt_ip ecy_ip;
	char colum_ip[32] = {0};
	short int a[num_ip][4] = {0};
	int fir_sec_thir = 0;
	int fir_colum = 0,sec_colum = 0,thir_colum = 0;
	
	//128 bit secret key
	unsigned char key[16] = {0x00}; 
	//expand key
    	unsigned char  expKey[4 * Nc * (Nr + 1)]; 
	unsigned char  out[16];
	unsigned char  dencrypt[16];
	unsigned int idx;
	
	//open output file
	if((fpd = fopen("output.txt","a+")) == NULL)
	{
		printf("open output file failure\n");
		return 0;
	}

	//open ip file
	if((fp = fopen("ip.txt","r")) == NULL)
	{
		printf("open ip.txt failed\n");
		return 0;
	}
	//read each ip
	while(fgets(buffer,20,fp) != NULL)
	{
		//printf("%s",buffer);
		split_str(buffer,temp);
	}

	printf("size struct encrypt_ip:%ld\n",sizeof(struct encrypt_ip));
#if 1
	printf("show ip\n");
	for(i = 0;i < 5;i++)
	{
		for(j = 0;j<4;j++)
		{
			printf("%#x ",temp[i].ip_h[j]);
		}
		putchar(10);
	}
#endif

	//fill session_num and len
	ecy_ip.session_num[0] = 0x00;
	ecy_ip.session_num[1] = 0x00;
	ecy_ip.session_num[2] = 0x10;
	ecy_ip.session_num[3] = 0x00;
	ecy_ip.len = 5;

	//get three colum to identify the five ip and fill to the struct ecy_ip 
#if 1
	while(1)
	{
		fir_sec_thir = get_thir_colum(temp,3,a,get_sec_colum(temp,2,a,get_fir_colum(temp,1,a)));
		if(fir_sec_thir == 0)
		{
			printf("it is the same ip\n");
			break;
		}
		else
		{
		
			//printf("fir_sec_thir:%d\n",fir_sec_thir);
			fir_colum = fir_sec_thir / 10000;
			sec_colum = (fir_sec_thir - fir_colum * 10000) / 100;
			thir_colum = fir_sec_thir % 100;

			//printf("fir_colum:%d sec_colum:%d thir_colum:%d\n",fir_colum,sec_colum,thir_colum);	
			break;
		}
	}
	ecy_ip = stor_index_as(ecy_ip,fir_colum,sec_colum,thir_colum,a);	
#endif

#if 0
	printf("index1:%d index2:%d index3:%d\n",ecy_ip.pi.index1,ecy_ip.pi.index2,ecy_ip.pi.index3);
	for(i = 0;i<5;i++)
	{
		printf("idx:%d\n",ecy_ip.pas[i].as);
	}
#endif
	//check_right(temp,fir_colum,sec_colum,thir_colum);


	
	//encrypt ip and fill the struct ecy_ip
	/****************encrypt and dencrypt*****************************************/
	for(i = 1;i < num_ip;i++)
	{
		memset(key,0,16);
		//fill the secret key
		memcpy(key,temp[i].ip_h,4);

		#if 1
   		printf ("***************secrte key***********************\n");  
		for (idx=0; idx<16; idx++) 
    		{
   	    		 printf ("%.2x ",key[idx]);
    		}
		printf("\n");
		#endif

		//expand the key and inital algorithm
		AES_ExpandKey(key,expKey);

		//inital the data will be encrypted
		if(i < num_ip -1)
		{
			memcpy(ecy_ip.aes[i-1].ip1_ip3_time,temp[i-1].ip_h,4);
			memcpy(ecy_ip.aes[i-1].ip1_ip3_time + 4,temp[i+1].ip_h,4);
		}
		else
		{
			memcpy(ecy_ip.aes[i-1].ip1_ip3_time,temp[i-1].ip_h,4);
			memcpy(ecy_ip.aes[i-1].ip1_ip3_time + 4,temp[0].ip_h,4);
				
		}
		
		//printf("data need to encrypt\n");
		//printf("%x\n",ecy_ip.aes[0].ip1_ip3_time);
	
		//encrypt the data
		AES_Encrypt(ecy_ip.aes[i-1].ip1_ip3_time,expKey,out);
		//memset(ecy_ip.aes + i-1,0,16);

		//copy the encrypt data to stuct
		memcpy(ecy_ip.aes[i-1].ip1_ip3_time,out,16);

		#if 1
		//show the encrypt data
   		printf ("*************encrypted data**************************\n");  
		for (idx=0; idx<16; idx++) 
    		{
   	    		 printf ("%.2x ",ecy_ip.aes[i-1].ip1_ip3_time[idx]);
    		}
		printf("\n");
		#endif

		AES_Decrypt(out,expKey,dencrypt);
		
		#if 1
   		printf ("*************dencrypted data**************************\n");  
		for (idx=0; idx<16; idx++) 
    		{
       			 printf ("%.2x ", dencrypt[idx]);
    		}
		printf("\n");
		printf("\n");
		#endif
		

	}
	/***********************end encrypt ip and fill**********************/


	#if 1
	//show the struct
	printf("********************show the struct*************************/\n");
	printf("session_num:%d\n",ecy_ip.session_num);
	printf("len:%d\n",ecy_ip.len);
	printf("index---->index1:%d index2:%d index3:%d\n",ecy_ip.pi.index1,ecy_ip.pi.index2,ecy_ip.pi.index3);
	printf("show path_as");
	for(i = 0;i<5;i++)
	{
		printf("ip%d: %d ",i,ecy_ip.pas[i].as);
	}
	printf("\n");
	printf("show encrypt struct:  ");
	for(i = 0;i<5;i++)
	{
		for (idx=0;idx<16;idx++) 
    		{
       			 printf ("%.2x ",ecy_ip.aes[i].ip1_ip3_time[idx]);
    		}
		printf("\n");
	}
	#endif

#if 0
	//print the struct to the output.txt
	fprintf(fpd,"%02x ",ecy_ip.session_num[0]);
	fprintf(fpd,"%02x ",ecy_ip.session_num[1]);
	fprintf(fpd,"%02x ",ecy_ip.session_num[2]);
	fprintf(fpd,"%02x ",ecy_ip.session_num[3]);
	fprintf(fpd,"%02x ",ecy_ip.len);
	fprintf(fpd,"%02x %02x %02x ",ecy_ip.pi.index1,ecy_ip.pi.index2,ecy_ip.pi.index3);
	//fprintf(fpd,"show path_as");
	for(i = 0;i<5;i++)
	{
		fprintf(fpd,"%02x ",ecy_ip.pas[i].as);
	}
	//fprintf(fpd,"\n");
	//fprintf(fpd,"show encrypt struct:  ");
	for(i = 0;i<5;i++)
	{
		for (idx=0;idx<16;idx++) 
    		{
       			fprintf (fpd,"%.02x ",ecy_ip.aes[i].ip1_ip3_time[idx]);
    		}
		//fprintf(fpd,"\n");
	}

#endif	

	printf("write_len:%d\n",fwrite(&ecy_ip,1,sizeof(struct encrypt_ip),fpd));	

	fclose(fp);
	fclose(fpd);
	return 0;
}
