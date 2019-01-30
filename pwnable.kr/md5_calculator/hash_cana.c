#include <stdio.h>
#include <stdlib.h>
#include <time.h>

int main(void)
{
	int rand_num[8];
	int i;
	int canary;

	srand(time(0));
	
	for(i=0;i<=7;i++)
	{
		rand_num[i] = rand();
	}

	scanf("%d",&i);
	//i = atoi(i);

	canary = i - rand_num[4] + rand_num[6] - rand_num[7] - rand_num[2] + rand_num[3] - rand_num[1] - rand_num[5];
	printf("0x%x\n",canary);

	return 0;
}
