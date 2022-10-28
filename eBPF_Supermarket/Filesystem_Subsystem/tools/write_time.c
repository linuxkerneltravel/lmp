#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <time.h>
 
#define TRUE 1
#define FORMAT "%.5d, %.4d-%.2d-%.2d %.2d:%.2d:%.2d\n"
#define REC_LEN 27    /* The bytes of one record, it depends on FORMAT */
int main(void)
{
	FILE * fp;
	struct tm * now;
	time_t sec;
	int index = 1;
	char temp[7];
	if((fp=fopen("write_time.txt", "a+"))==NULL)
	{
		perror("Open the file log.txt : ");
		exit(EXIT_FAILURE);
	}
	if(!fseek(fp, (-1) * REC_LEN, SEEK_END))
	{
		fgets(temp, sizeof(temp)-1, fp);
		printf("%s\n", temp);
		index = (int)strtol(temp, NULL, 10) + 1;
	}
	fseek(fp, 0, SEEK_END);
	while(TRUE)
	{
		time(&sec);
		now = localtime(&sec);
		fprintf(fp, FORMAT, index, now->tm_year+1900, now->tm_mon+1, now->tm_mday, 
			now->tm_hour, now->tm_min, now->tm_sec);
		index++;
		fflush(fp);
		sleep(1);
	}
	fclose(fp);
	return 0;
}