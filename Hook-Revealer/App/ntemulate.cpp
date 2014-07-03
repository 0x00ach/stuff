#include "hook_revealer.h"

NTSTATUS (__stdcall *myNtQueryDirectoryFile)(
 HANDLE FileHandle,
 HANDLE Event,
 PIO_APC_ROUTINE ApcRoutine,
 PVOID ApcContext,
 PIO_STATUS_BLOCK IoStatusBlock,
 PVOID FileInformation,
 ULONG Length,
 FILE_INFORMATION_CLASS FileInformationClass,
 BOOLEAN ReturnSingleEntry,
 PUNICODE_STRING FileName,
 BOOLEAN RestartScan
);
NTSTATUS (__stdcall *myNtOpenFile)(
  PHANDLE FileHandle,
  ACCESS_MASK DesiredAccess,
  POBJECT_ATTRIBUTES ObjectAttributes,
  PIO_STATUS_BLOCK IoStatusBlock,
  ULONG ShareAccess,
  ULONG OpenOptions
);
NTSTATUS (__stdcall *myNtReadFile)(
    HANDLE FileHandle,
    HANDLE Event,
    PIO_APC_ROUTINE ApcRoutine,
    PVOID ApcContext,
	PIO_STATUS_BLOCK IoStatusBlock,
    PVOID Buffer,
    ULONG Length,
    PLARGE_INTEGER ByteOffset,
    PULONG Key
);
NTSTATUS (__stdcall *myNtReadVirtualMemory)(
  HANDLE ProcessHandle,
  PVOID BaseAddress,
  PVOID Buffer,
  ULONG NumberOfBytesToRead,
  PULONG NumberOfBytesReaded OPTIONAL
);
NTSTATUS (__stdcall *myNtOpenProcess)(
  PHANDLE ProcessHandle,
  ACCESS_MASK AccessMask,
  POBJECT_ATTRIBUTES ObjectAttributes,
  PCLIENT_ID ClientId
);
NTSTATUS (__stdcall *myNtQueryInformationProcess)(
  HANDLE ProcessHandle,
  ULONG ProcessInformationClass,
  PVOID ProcessInformation,
  ULONG ProcessInformationLength,
  PULONG ReturnLength
);

void analysis::initiateNtEmulations()
{
	DWORD OpenFileSyscallNumber=*(PDWORD)((DWORD)(GetProcAddress(GetModuleHandleA("ntdll.dll"), "ZwOpenFile"))+1);
	initOF((PBYTE*)&myNtOpenFile, OpenFileSyscallNumber);
	
	DWORD ReadFileSyscallNumber=*(PDWORD)((DWORD)(GetProcAddress(GetModuleHandleA("ntdll.dll"), "ZwReadFile"))+1);
	initRF((PBYTE*)&myNtReadFile, ReadFileSyscallNumber);
	
	DWORD QueryDirectoryFileFileSyscallNumber=*(PDWORD)((DWORD)(GetProcAddress(GetModuleHandleA("ntdll.dll"), "ZwQueryDirectoryFile"))+1);
	initQDF((PBYTE*)&myNtQueryDirectoryFile, QueryDirectoryFileFileSyscallNumber);
	
	DWORD ReadVirtualMemorySyscallNumber=*(PDWORD)((DWORD)(GetProcAddress(GetModuleHandleA("ntdll.dll"), "ZwReadVirtualMemory"))+1);
	initRVM((PBYTE*)&myNtReadVirtualMemory, ReadVirtualMemorySyscallNumber);

	DWORD OpenProcessNumber=*(PDWORD)((DWORD)(GetProcAddress(GetModuleHandleA("ntdll.dll"), "ZwOpenProcess"))+1);
	initOP((PBYTE*)&myNtOpenProcess, OpenProcessNumber);

	DWORD QueryInformationProcessNumber=*(PDWORD)((DWORD)(GetProcAddress(GetModuleHandleA("ntdll.dll"), "ZwQueryInformationProcess"))+1);
	initQIP((PBYTE*)&myNtQueryInformationProcess, QueryInformationProcessNumber);
}

DWORD analysis::readDw(DWORD addr)
{
	DWORD ret;
	ULONG size;
	if(myNtReadVirtualMemory(currentProcessHandle, (PVOID)addr, &ret, 4, &size)==STATUS_SUCCESS)
		return ret;
	else
		return 0;
}

WORD analysis::readW(DWORD addr)
{
	WORD ret;
	ULONG size;
	if(myNtReadVirtualMemory(currentProcessHandle, (PVOID)addr, &ret, 2, &size)==STATUS_SUCCESS)
		return ret;
	else
		return 0;
}

BYTE analysis::readB(DWORD addr)
{
	BYTE ret;
	ULONG size;
	if(myNtReadVirtualMemory(currentProcessHandle, (PVOID)addr, &ret, 1, &size)==STATUS_SUCCESS)
	{
		return ret;
	}
	else
		return 0;
}

BOOL analysis::readMem(DWORD addr, PVOID buffer, ULONG nbBytes)
{
	ULONG size;
	if(myNtReadVirtualMemory(currentProcessHandle, (PVOID)addr, buffer, nbBytes, &size)==STATUS_SUCCESS)
		return true;
	else
		return false;
}

void initQIP(PBYTE* funcAddr, DWORD syscallnum)
{
	
	PBYTE func;

	*funcAddr=(PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 15);
	func=*funcAddr;
	*func=0xB8; //mov eax
	*(PDWORD)(func+1)=syscallnum; //syscall number
	*(PDWORD)(func+5)=0xC283D48B; //mov edx, esp    //add edx, 4
	*(func+9)=0x04;
	*(PWORD)(func+10)=0x2ECD;  // int 2E
	*(PWORD)(func+12)=0x14C2; //retn 14
	*(func+14)=0x00;

	DWORD oldProtec;
	VirtualProtect((PVOID)*funcAddr, 15, PAGE_EXECUTE_READWRITE, &oldProtec);
	#if _DEBUG
		printf(" Copying Query Information Process at 0x%x\n", *funcAddr);
		system("pause");
	#else
	#endif
}
void initOP(PBYTE* funcAddr, DWORD syscallnum)
{
	PBYTE func;

	*funcAddr=(PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 15);
	func=*funcAddr;
	*func=0xB8; //mov eax
	*(PDWORD)(func+1)=syscallnum; //syscall number
	*(PDWORD)(func+5)=0xC283D48B; //mov edx, esp    //add edx, 4
	*(func+9)=0x04;
	*(PWORD)(func+10)=0x2ECD;  // int 2E
	*(PWORD)(func+12)=0x10C2; //retn 10
	*(func+14)=0x00;

	DWORD oldProtec;
	VirtualProtect((PVOID)*funcAddr, 15, PAGE_EXECUTE_READWRITE, &oldProtec);
	#if _DEBUG
		printf(" Copying Open Process at 0x%x\n", *funcAddr);
		system("pause");
	#else
	#endif
}

//NtOpenFile init
void initOF(PBYTE* funcAddr, DWORD syscallnum)
{
	PBYTE func;

	*funcAddr=(PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 15);
	func=*funcAddr;
	*func=0xB8; //mov eax
	*(PDWORD)(func+1)=syscallnum; //syscall number
	*(PDWORD)(func+5)=0xC283D48B; //mov edx, esp    //add edx, 4
	*(func+9)=0x04;
	*(PWORD)(func+10)=0x2ECD;  // int 2E
	*(PWORD)(func+12)=0x18C2; //retn 18
	*(func+14)=0x00;

	DWORD oldProtec;
	VirtualProtect((PVOID)*funcAddr, 15, PAGE_EXECUTE_READWRITE, &oldProtec);
	#if _DEBUG
		printf(" Copying Open File at 0x%x\n", *funcAddr);
		system("pause");
	#else
	#endif
}
//NtReadFile init
void initRF(PBYTE* funcAddr, DWORD syscallnum)
{
	PBYTE func;

	*funcAddr=(PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 15);
	func=*funcAddr;
	*func=0xB8; //mov eax
	*(PDWORD)(func+1)=syscallnum; //syscall number
	*(PDWORD)(func+5)=0xC283D48B; //mov edx, esp    //add edx, 4
	*(func+9)=0x04;
	*(PWORD)(func+10)=0x2ECD;  // int 2E
	*(PWORD)(func+12)=0x24C2; //retn 18
	*(func+14)=0x00;

	DWORD oldProtec;
	VirtualProtect((PVOID)*funcAddr, 15, PAGE_EXECUTE_READWRITE, &oldProtec);
	#if _DEBUG
		printf(" Copying Read File at 0x%x\n", *funcAddr);
		system("pause");
	#else
	#endif

}
//NtReadVirtualMemory
void initRVM(PBYTE* funcAddr, DWORD syscallnum)
{
	PBYTE func;

	*funcAddr=(PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 15);
	func=*funcAddr;
	*func=0xB8; //mov eax
	*(PDWORD)(func+1)=syscallnum; //syscall number
	*(PDWORD)(func+5)=0xC283D48B; //mov edx, esp    //add edx, 4
	*(func+9)=0x04;
	*(PWORD)(func+10)=0x2ECD;  // int 2E
	*(PWORD)(func+12)=0x14C2; //retn 14
	*(func+14)=0x00;

	DWORD oldProtec;
	VirtualProtect((PVOID)*funcAddr, 15, PAGE_EXECUTE_READWRITE, &oldProtec);
	#if _DEBUG
		printf(" Copying Read Virtual Memory at 0x%x\n", funcAddr);
		system("pause");
	#else
	#endif

}
//NtQueryDirectoryFile
void initQDF(PBYTE* funcAddr, DWORD syscallnum)
{
	PBYTE func;

	*funcAddr=(PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 15);
	func=*funcAddr;
	*func=0xB8; //mov eax
	*(PDWORD)(func+1)=syscallnum; //syscall number
	*(PDWORD)(func+5)=0xC283D48B; //mov edx, esp    //add edx, 4
	*(func+9)=0x04;
	*(PWORD)(func+10)=0x2ECD;  // int 2E
	*(PWORD)(func+12)=0x2CC2; //retn 2C
	*(func+14)=0x00;

	DWORD oldProtec;
	VirtualProtect((PVOID)*funcAddr, 15, PAGE_EXECUTE_READWRITE, &oldProtec);
	#if _DEBUG
		printf(" Copying Query Directory File at 0x%x\n", funcAddr);
		system("pause");
	#else
	#endif

}


DWORD readFile(PWSTR fileName, PBYTE buffer, int bufferLen, int fileOffset, int* nbBytesRead)
{
	//nom du fichier
	UNICODE_STRING path;
	path.Buffer=fileName;
	path.Length = (USHORT)wcslen(fileName)*2;
	//handle sur le fichier
	HANDLE fhandle = NULL;
	OBJECT_ATTRIBUTES obj;
	//retour de fonction
	IO_STATUS_BLOCK retVal;
	LARGE_INTEGER byteOffset;

	//+2 car wcslen n'inclue pas les 0x00 terminaux, et on en a deux
	//même si dans ce cas, le buffer ne sera pas utilisé
	path.MaximumLength=path.Length+2; 

	//lecture du fichier, attributs
	obj.Length=sizeof(OBJECT_ATTRIBUTES);
	obj.RootDirectory=NULL;
	obj.Attributes=OBJ_CASE_INSENSITIVE;
	obj.ObjectName=&path;
	obj.SecurityDescriptor=NULL;
	obj.SecurityQualityOfService=NULL;

	//offset où se positionner
	byteOffset.LowPart = fileOffset;
	byteOffset.HighPart = 0;

	if(myNtOpenFile(&fhandle, GENERIC_READ, &obj, &retVal, FILE_SHARE_READ, FILE_NON_DIRECTORY_FILE)==STATUS_SUCCESS)
	{
		if(myNtReadFile(fhandle, NULL, NULL, NULL, &retVal, buffer, bufferLen, &byteOffset, NULL)==STATUS_SUCCESS)
		{
			*nbBytesRead=retVal.Information;
			CloseHandle(fhandle);
			return 1;
		}
		else
			CloseHandle(fhandle);
	}
	
	return 0;
}