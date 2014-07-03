/********************************
	Poison Ivy memory scanner
	Last modified: 05/23/2013

	Searchs for different patterns in running processes to identify Poison Ivy signatures.

********************************/

// use multi-byte string format, not unicode
#ifdef UNICODE
	#undef UNICODE
#endif

// Console debug output
// #define DEBUG 1

#include <windows.h>		// system interaction
#include <stdio.h>			// output functions
#include <tlhelp32.h>		// enumerating process


// process memory region
typedef struct _memoryRegion
{
	ULONG baseAddress;		// base address
	ULONG size;				// size
	ULONG type;				// memory type
	ULONG protect;			// protection (mask!)
	ULONG state;			// memory state
	PVOID blink;			// next region
}memoryRegion, *pmemoryRegion;

// memory pattern
typedef struct _mempattern
{
	ULONG protect;			// memory protection
	WORD patternId;			// pattern unique identifier
	ULONG patternlen;		// pattern length
	PVOID pattern;			// BYTE[pattern length] pattern
	PVOID flink;
}mempattern, *pmempattern;


// get SE_DEBUG_NAME privilege
DWORD elevate_access_rights();

// lists and scans running processes
DWORD __fastcall memscan(
	_In_ pmempattern mempatterns
);

// scans a running process
DWORD __fastcall processMemScan(
	_In_ ULONG pid,
	_In_ pmempattern mempatterns
);

// scans a memory region for a pattern
PVOID __stdcall searchMem(
	_In_ PVOID needle,
	_In_ ULONG needleLen,
	_In_ PVOID memory,
	_In_ ULONG memoryLen
);

// main :]
int main(int argc, char** argv)
{
	pmempattern list, current;
	BYTE pattern1[]={
			0x5E,0x81,0xC6,0xFB,0x01,0x00,0x00,0x8D,
			0xBD,0x84,0xF0,0xFF,0xFF,0x0F,0xB7,0x06,
			0x0F,0xB7,0x4E,0x02,0x83,0xC6,0x04,0x03,
			0xC7,0x51,0x51,0x56,0x50,0xFF,0x95,0x2D,
			0xF1,0xFF,0xFF,0x59,0x03,0xF1,0x66,0x83,
			0x3E,0x00,0x75,0xE1,0x83,0xC6,0x02,0x89,
			0x75,0xF8,0x66,0x83,0x3E,0x00,0x74,0x11,
			0x0F,0xB7,0x06,0x0F,0xB7,0x4E,0x02,0x83
	};
	BYTE pattern2[]={
			0x55,0x8B,0xEC,0x81,0xC4,0x30,0xFA,0xFF,
			0xFF,0x8B,0x75,0x08,0x8D,0x86,0xFB,0x03,
			0x00,0x00,0x50,0x6A,0x00,0x6A,0x00,0xFF,
			0x96,0x85,0x00,0x00,0x00,0x89,0x86,0xC5,
			0x08,0x00,0x00,0xFF,0x96,0x89,0x00,0x00,
			0x00,0x3D,0xB7,0x00,0x00,0x00,0x75,0x04,
			0xC9,0xC2,0x04,0x00,0x56,0x8D,0x86,0x6B,
			0x09,0x00,0x00,0x50,0x8D,0x86,0x45,0x01
	};
	char pattern3[]="\x18\x04\x28\x00SOFTWARE\\Classes\\http\\shell\\open\\command";
	char pattern4[]="\x04\x35\x00\x53Software\\Microsoft\\Active Setup\\Installed Components\\";
	char pattern5[]="\x0f\x04\x08\x00StubPath";

	current = NULL;
	list = (pmempattern)malloc(sizeof(mempattern));
	list->patternId = 1;
	list->pattern = pattern1;
	list->patternlen = sizeof(pattern1);
	list->protect = PAGE_EXECUTE_READWRITE;
	list->flink = current;
	current = list;

	list = (pmempattern)malloc(sizeof(mempattern));
	list->patternId = 2;
	list->pattern = pattern2;
	list->patternlen = sizeof(pattern2);
	list->protect = PAGE_EXECUTE_READWRITE;
	list->flink = current;
	current = list;

	list = (pmempattern)malloc(sizeof(mempattern));
	list->patternId = 3;
	list->pattern = pattern3;
	list->patternlen = sizeof(pattern3)-1;
	list->protect = PAGE_EXECUTE_READWRITE;
	list->flink = current;
	current = list;

	list = (pmempattern)malloc(sizeof(mempattern));
	list->patternId = 4;
	list->pattern = pattern4;
	list->patternlen = sizeof(pattern4)-1;
	list->protect = PAGE_EXECUTE_READWRITE;
	list->flink = current;
	current = list;

	list = (pmempattern)malloc(sizeof(mempattern));
	list->patternId = 5;
	list->pattern = pattern5;
	list->patternlen = sizeof(pattern5)-1;
	list->protect = PAGE_EXECUTE_READWRITE;
	list->flink = current;

	printf("Find PIVY!\n");
	
	elevate_access_rights();

	if(memscan(list)==ERROR_VIRUS_INFECTED)
		printf("\n\nPIVY found.\n");

	current = list;
	while(current!=NULL)
	{
		list = current;
		current = (pmempattern)(current->flink);
		free(list);
	}

	system("pause");
	return 0;
}

/********************************
	Obtains the SeDebugPrivilege privilege to access other process memory.
	
	return Value
		ERROR_SUCCESS : no error
		ERROR_ACCESS_DENIED : cannot obtain the SeDebugPrivilege privilege
********************************/
DWORD elevate_access_rights()
{
	TOKEN_PRIVILEGES priv;
	HANDLE n1;
	LUID luid;
	if(!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY, &n1))
	{
		#ifdef DEBUG
			printf("[!] elevate_access_rights :: OpenProcessToken() failed\n");
		#endif
		return ERROR_ACCESS_DENIED;
	}
	if(!LookupPrivilegeValueA(NULL, "SeDebugPrivilege", &luid))
	{
		#ifdef DEBUG
			printf("[!] elevate_access_rights :: LookupPrivilegeValueA() failed\n");
		#endif
		return ERROR_ACCESS_DENIED;
	}
	priv.PrivilegeCount=1;
	priv.Privileges[0].Luid=luid;
	priv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	if(!AdjustTokenPrivileges(n1, FALSE, &priv, sizeof(priv), NULL, NULL))
	{
		#ifdef DEBUG
			printf("[!] elevate_access_rights :: AdjustTokenPrivileges() failed\n");
		#endif
		return ERROR_ACCESS_DENIED;
	}
	
	CloseHandle(n1);
	return ERROR_SUCCESS;
}


/********************************
	Enumerate running processes and initiate their memory scan.

	parameters
		pmempattern mempatterns [in]
			Memory patterns linked list.
	
	return Value
		ERROR_SUCCESS : no error
		ERROR_INVALID_PARAMETER : mempatterns is NULL
		ERROR_VIRUS_INFECTED : a pattern matched
		ERROR_ACCESS_DENIED : cannot obtain the SeDebugPrivilege privilege
		ERROR_OPEN_FAILED : cannot list processes
********************************/
DWORD __fastcall memscan(
	_In_ pmempattern mempatterns)
{
	HANDLE hThlp;
	PROCESSENTRY32 pe;
	DWORD found;
	DWORD retval;

	if(mempatterns == NULL)
		return ERROR_INVALID_PARAMETER;

	found = ERROR_SUCCESS;
	pe.dwSize=sizeof(PROCESSENTRY32);

	if(elevate_access_rights() !=  ERROR_SUCCESS)
	{
		printf("[!] Insufficient privileges.\n");
		return ERROR_ACCESS_DENIED;
	}

	// Enumerates the running process list
	hThlp=CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);
	if(hThlp==INVALID_HANDLE_VALUE)
	{
		printf("[!] Process enumeration impossible.\n");
		#ifdef DEBUG
			printf("[!] memscan :: CreateToolhelp32Snapshot failed.\n");
		#endif
		return ERROR_OPEN_FAILED;
	}

	if(!Process32First(hThlp,&pe))
	{
		printf("[!] Process enumeration impossible\n");
		#ifdef DEBUG
			printf("[!] memscan :: Process32First failed.\n");
		#endif
		CloseHandle(hThlp);
		return ERROR_OPEN_FAILED;
	}

	do
	{
		if(pe.th32ProcessID!=0 && pe.th32ProcessID!=GetCurrentProcessId())
		{
			printf("\t[-] Scan %s...",pe.szExeFile);

			retval = processMemScan(pe.th32ProcessID,mempatterns);
			if(retval == ERROR_VIRUS_INFECTED)
			{
				found = ERROR_VIRUS_INFECTED;
			}
			else if(retval == ERROR_SUCCESS)
			{
				printf(" CLEAN.\n");
			}
		}
	}while(Process32Next(hThlp,&pe));

	CloseHandle(hThlp);

	return found;
}


/********************************
	Scans a running process for patterns

	parameters
		ULONG pid [in]
			Process identifier
		pmempattern mempatterns [in]
			Memory patterns linked list
	
	return Value
		ERROR_SUCCESS : no error
		ERROR_VIRUS_INFECTED : a pattern matched
		ERROR_ACCESS_DENIED : cannot open process
********************************/
DWORD __fastcall processMemScan(
	_In_ ULONG pid,
	_In_ pmempattern mempatterns)
{
	HANDLE hProcess;
	pmempattern currentPattern = mempatterns;
	BOOL continueScan;
	DWORD found = ERROR_SUCCESS;
	PVOID regionMemory;
	PVOID match;
	ULONG i = 0;
	MEMORY_BASIC_INFORMATION mbi;
	pmemoryRegion last, current;
	DWORD dwRead;
	last=NULL;

	if(pid == 0 || mempatterns == NULL)
	{
		return ERROR_INVALID_PARAMETER;
	}
	// opens the process with minimal required access rights.
	hProcess = OpenProcess(PROCESS_VM_READ|PROCESS_QUERY_INFORMATION,FALSE,pid);
	if(hProcess==NULL)
	{
		printf("\n\t\t[!] Cannot scan process.\n ");
		#ifdef DEBUG
			printf("\n\t\t[!] processMemScan :: OpenProcess() failed.\n",pid);
		#endif
		return ERROR_ACCESS_DENIED;
	}

	// gather the virtual memory regions of the process
	for(i = 1; VirtualQueryEx(hProcess,(PVOID)i,&mbi,sizeof(MEMORY_BASIC_INFORMATION))==sizeof(mbi) ; i += mbi.RegionSize)
	{
		current = (pmemoryRegion)malloc(sizeof(memoryRegion));
		current->baseAddress=(ULONG)mbi.BaseAddress;
		current->size=mbi.RegionSize;
		current->protect=mbi.Protect;
		current->state=mbi.State;
		current->type=mbi.Type;
		current->blink=last;
		last=current;
	}

	// For each memory region
	while(current!=NULL)
	{
		// Search the pattern
		currentPattern=mempatterns;
		while(currentPattern != NULL)
		{
			continueScan = TRUE;
			// Memory access test
			if(currentPattern->protect!=0)
			{
				// tests the memory access rights 
				if((currentPattern->protect & current->protect) == 0)
				{
					continueScan=FALSE;
				}
			}

			if(continueScan)
			{
				regionMemory = malloc(current->size);
				
				// copy the whole memory region
				if(ReadProcessMemory(hProcess,(PVOID)current->baseAddress,regionMemory,current->size,&dwRead)!=0)
				{
					// searchs the memory for the current pattern
					match = searchMem(currentPattern->pattern,currentPattern->patternlen,regionMemory, current->size);
					while(match != NULL)
					{
						found = ERROR_VIRUS_INFECTED;

						// match
						printf("\n\t\t[-] Pattern %d matched at 0x%.8x\n",currentPattern->patternId, ((ULONG)match-(ULONG)regionMemory+current->baseAddress));

						// other ones?
						match = (PVOID)((ULONG)match+currentPattern->patternlen);
						match = searchMem(currentPattern->pattern,currentPattern->patternlen,match, ((ULONG)regionMemory + current->size - (ULONG)match));
					}
				}

				free(regionMemory);
			}
			// next pattern
			currentPattern = (pmempattern)currentPattern->flink;
		}
		// next memory region
		current=(pmemoryRegion)current->blink;
	}

	// free
	current = last;
	while(current != NULL)
	{
		last = (pmemoryRegion)current->blink;
		free(current);
		current = last;
	}

	return found;
}

/********************************
	Searchs "needle" in "memory" space. The respective lengths are needleLen and memoryLen.

	/!\ NO CHECKS PERFORMED ON SUPPLIED PARAMETERS /!\


	parameters
		PVOID needle [in]
			"needleLen" memory region descripting the pattern we want to search for
		ULONG needleLen [in]
			"needle" length, in bytes
		PVOID memory [in]
			"memoryLen" memory region where we will try to find needle
		ULONG memoryLen [in]
			"memory" length, in bytes
	
	return Value
		NULL : needle could not be found
		NON-NULL : a valid pointer on the pattern matched

********************************/
__declspec(naked) PVOID __stdcall searchMem(
	_In_ PVOID needle,
	_In_ ULONG needleLen,
	_In_ PVOID memory, 
	_In_ ULONG memoryLen)
{
	__asm
	{
		push ebp
		mov ebp, esp
		push esi
		push edi
		push ebx

		mov eax, memory		// memory regions pointers
		mov edx, needle
		mov edi, needleLen	// memory regions lengths
		mov esi, memoryLen
			
		loop1:		// first loop: reads the memory region
			add esi, eax
			xor ecx, ecx

				loop2:	// second loop: searchs the current memory pointer for the pattern
				mov bl, byte ptr ds:[edx+ecx]
				cmp bl, byte ptr ds:[eax+ecx]
				jnz breakloop2
				add ecx,1
				cmp ecx, edi
				jnz loop2

			jmp epilogFound
			
			breakloop2:
			add eax, 1	
			sub esi, eax
			jz epilogNotFound	
			cmp esi, edi		
			jnz loop1
			
		epilogNotFound:
		xor eax,eax			// return NULL
			
		epilogFound:
		pop ebx			// restore registers
		pop edi
		pop esi
		mov esp, ebp
		pop ebp
		ret 0x10
	}
}

