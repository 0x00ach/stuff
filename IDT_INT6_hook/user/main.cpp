#include <windows.h>
#include <stdio.h>

int main(int argc, char** argv)
{
	BYTE shellcode[] = {0xFF,0xFF,0xFF,0xFF,0xC3};
	DWORD addr;
	DWORD old;


	printf("Press a key to fault:\n");
	system("pause");

	VirtualProtect(&shellcode, 2, PAGE_EXECUTE_READWRITE, &old);
	addr = (DWORD)&shellcode;
	__asm
	{
        mov eax, addr
		call eax
	}
	
	printf("faulted (wait, what?)\n");
	system("pause");
	return 0;

}