#include <stdio.h>
#include <string.h>

int main()
{
	FILE *fp;
	int len = 0,i = 0;
	unsigned char *buff = NULL;

	if((fp = fopen("output.txt","r")) == NULL)
	{
		printf("open file error\n");
	}
	fseek(fp,0,SEEK_SET);
	fseek(fp,0,SEEK_END);
	len = ftell(fp);
	printf("len:%d\n",len);
	fseek(fp,0,SEEK_SET);
	buff = malloc(len);
	printf("%d \n",fread(buff,1,len,fp));
	for(i = 0;i<len;i++)
	{
		printf("%02x  ",buff[i]);
	}
	return 0;
}
