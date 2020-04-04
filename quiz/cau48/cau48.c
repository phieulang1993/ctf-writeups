// gcc cau48.c -m32 -o cau48 -fno-stack-protector

#include<stdio.h>
#include<stdlib.h>
#include<string.h>

char global[0x200];
int f1();
int x(int p0, int p1);
int main()
{
	f1();
}

int f(){
	char str[0x100];
	fgets(global, 0x200, stdin);
	strncpy(str, global, 0x100);
	sprintf(global, "Hello %s\n", str);
	printf("global len: %#x", strlen(global));
	exit(1);
}
int f1()
{
	char s[0x200];
	memset(s, 'B', 0x200);
	x(0x90909090, 0x90909090);
	f();
}
int x(int p0, int p1){
	return p0+p1;
}