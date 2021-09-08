#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(){
	while(1){
		printf("pid: %d\n", getpid());
		sleep(10);
	}
}