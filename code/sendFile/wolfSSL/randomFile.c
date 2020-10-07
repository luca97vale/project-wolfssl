#include <stdio.h>
#include <errno.h>
#include <stdlib.h>

int main(int argc, char **argv)	{
	FILE *fp;
    fp = fopen ("sample.txt","w");
    if (fp == NULL) {
        printf ("File not created okay, errno = %d\n", errno);
        return 1;
    }
    int bytes = atoi(argv[1]);
    for(int i=0;i<bytes;i++){
		fprintf (fp, "X"); 
	}
    fclose (fp);
    
    return 0;
}
