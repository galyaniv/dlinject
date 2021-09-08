#include <stdio.h>
#include <dlfcn.h>

void hello()
{
	printf("I just got loaded\n");
}

__attribute__((constructor))
void loadMsg()
{
	hello();
}