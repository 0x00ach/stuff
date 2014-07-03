#include <windows.h>
#include <stdio.h>
typedef unsigned long long QWORD;
typedef QWORD* PQWORD;

typedef BOOL (WINAPI* CREATEPROCESSAFUNCTION)(LPCTSTR,LPTSTR,LPSECURITY_ATTRIBUTES,LPSECURITY_ATTRIBUTES,BOOL,DWORD,LPVOID,LPCTSTR,LPSTARTUPINFO,LPPROCESS_INFORMATION);
CREATEPROCESSAFUNCTION oldCreateProcessA;

BOOL WINAPI MyCreateProcessA(
  _In_opt_     LPCTSTR lpApplicationName,
  _Inout_opt_  LPTSTR lpCommandLine,
  _In_opt_     LPSECURITY_ATTRIBUTES lpProcessAttributes,
  _In_opt_     LPSECURITY_ATTRIBUTES lpThreadAttributes,
  _In_         BOOL bInheritHandles,
  _In_         DWORD dwCreationFlags,
  _In_opt_     LPVOID lpEnvironment,
  _In_opt_     LPCTSTR lpCurrentDirectory,
  _In_         LPSTARTUPINFO lpStartupInfo,
  _Out_        LPPROCESS_INFORMATION lpProcessInformation
)
{
	int retValue = oldCreateProcessA(lpApplicationName,lpCommandLine,lpProcessAttributes,lpThreadAttributes,bInheritHandles,
		dwCreationFlags,lpEnvironment,lpCurrentDirectory,lpStartupInfo,lpProcessInformation);

	printf("[o] MyCreateProcessA called, args :\n"
		"\tlpApplicationName\t%s\n"
		"\tlpCommandLine\t%s\n"
		"\tlpProcessAttributes\t%x\n"
		"\tlpThreadAttributes\t%x\n"
		"\tbInheritHandles\t%x\n"
		"\tdwCreationFlags\t%x\n"
		"\tlpEnvironment\t%x\n"
		"\tlpCurrentDirectory\t%x\n"
		"\tlpStartupInfo\t%x\n"
		"\tlpProcessInformation\n",lpApplicationName,lpCommandLine,lpProcessAttributes,lpThreadAttributes,bInheritHandles,
		dwCreationFlags,lpEnvironment,lpCurrentDirectory,lpStartupInfo,lpProcessInformation);

	return retValue;
}

QWORD revert(QWORD src)
{
	QWORD d = 0;

	for (int i =0; i<8; i++)
	{
		d = d + (((src >> ((7-i)*8)) & 0x00000000000000FF) << (i*8));
	}

	return d;
}

int main(int argc, char** argv)
{
	DWORD oldP;
	QWORD legitAddr = (QWORD)GetProcAddress(LoadLibraryA("kernel32.dll"),"CreateProcessA");
	QWORD ourAddr = (QWORD)MyCreateProcessA;
	BYTE trampoline[0x18] = {
		0x4c,0x8b,0xdc,0x48,0x83,0xec,0x68,0x49,
		0x83,0x63,0xf0,0x00,0x48,0xB8,0x88,0x77,
		0x66,0x55,0x44,0x33,0x22,0x11,0xff,0xe0
	};

	oldCreateProcessA = (CREATEPROCESSAFUNCTION)(PVOID)trampoline;

	printf("[-] Adresses memoire :\n");
	printf("\t[+] CreateProcessA\t0x%llx\n", legitAddr);
	printf("\t[+] MyCreateProcessA\t0x%llx\n", ourAddr);
	printf("\t[+] Trampoline\t\t0x%llx\n", trampoline);
	printf("\t[+] oldCreateProcessA\t0x%llx\n", oldCreateProcessA);

	printf("[-] Patch trampoline\n");
	*((PQWORD)((PBYTE)trampoline+0x0e))=legitAddr+0xc;

	printf("[-] Protection memoire\n");
	if(!VirtualProtect((PVOID)trampoline,0x18,PAGE_EXECUTE_READWRITE,&oldP))
	{
		printf("[!] Erreur VProtec trampoline.\n");
		return -1;
	}
	if(!VirtualProtect((PVOID)legitAddr,12,PAGE_EXECUTE_READWRITE,&oldP))
	{
		printf("[!] Erreur VProtec CreateProcessA.\n");
		return -1;
	}
	
	printf("[-] Installation hook\n");
	*((PBYTE)legitAddr)=0x48;
	*((PBYTE)legitAddr+1)=0xB8;
	*((PQWORD)(legitAddr+2))=ourAddr;
	*((PBYTE)(legitAddr+10))=0xff;
	*((PBYTE)(legitAddr+11))=0xe0;

	printf("[-] Reprotection memoire\n");
	if(!VirtualProtect((PVOID)legitAddr,12,oldP,&oldP))
	{
		printf("[!] Erreur VProtec CreateProcessA.\n");
		return -1;
	}

	printf("[-] system(\"pause\")\n");
	system("pause");

	printf("[-] fini :]\n");

	system("pause");
	return 0;
}