#include "inf.h"

int main(int argc, char** argv)
{
	if(argc > 2)
	{
		printf("Return 0x%x\n", infect_file(argv[1], argv[2]));
	}
	else
		printf("Usage : %s PE_file DLL_name\n", argv[0]);
	
	system("pause");
}