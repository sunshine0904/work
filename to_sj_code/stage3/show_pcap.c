#include <stdio.h>
#include <stdlib.h>


int main()
{
	FILE *fp;
	int i = 0,len = 0;
	unsigned char *buff = NULL;

	if((fp = fopen("output.txt","r")) == NULL)
	{
		printf("open failed");
		exit(0);
	}
	fseek(fp,0,SEEK_SET);
	fseek(fp,0,SEEK_END);
	len = ftell(fp);
	printf("len:%d\n",len);
	buff = (unsigned char *)malloc(len);
	fseek(fp,0,SEEK_SET);
	printf("read:%d\n",fread(buff,1,len,fp));
	for(i = 0;i<len;i++)
	{
		printf("%02x ",buff[i]);
		if(i %100 ==0)
		{
			putchar(10);
		}
	}
	putchar(10);

	return 0;
	
}
