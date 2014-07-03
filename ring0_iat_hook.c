#include <ntddk.h>

NTSYSAPI
NTSTATUS
NTAPI ZwQuerySystemInformation(
IN ULONG SystemInformationClass,
			IN PVOID SystemInformation,
			IN ULONG SystemInformationLength,
			OUT PULONG ReturnLength);

//function type
typedef NTSTATUS (*ZWQUERYSYSTEMINFORMATION)(
	ULONG SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength
);
ZWQUERYSYSTEMINFORMATION TrueZwQuerySystemInformation;

NTSTATUS MyZwQuerySystemInformation(
ULONG SystemInformationClass,
PVOID SystemInformation,
ULONG SystemInformationLength,
PULONG ReturnLength)
{
	
	NTSTATUS temp;
	DbgPrint("[-] hook function called with args : %x %x %x %x\n", SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
	temp=TrueZwQuerySystemInformation(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
	DbgPrint("[-] returning 0x%x\n", temp);
	return temp;
}

VOID unload(PDRIVER_OBJECT pDriverObject)
{
	DbgPrint("--- HOOK IAT bye bye ! ---");
}

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegistryPath)
{
	ULONG start, end, i;
	NTSTATUS ret;
	
	DbgPrint("--- HOOK IAT DRIVER ENTRY---\n");
    pDriverObject->DriverUnload = unload;
	 
	TrueZwQuerySystemInformation = &ZwQuerySystemInformation;
	DbgPrint("[-] ZwQuerySystemInformation : 0x%x\n", TrueZwQuerySystemInformation);
	
	start = (ULONG)(pDriverObject->DriverStart); //RVA pe offset
	start = start + 0x3C; //pe offset
	start = *(PULONG)start; //RVA du PE
	start = start + (ULONG)(pDriverObject->DriverStart); //adresse du PE
	end = start +  0xDC; //addr sizeOfIat
	start = start + 0xD8; //addr RVA IAT
	start = *(PULONG)start; //RVA IAT
	end = *(PULONG)end; //sizeOfIat
	start = start + (ULONG)(pDriverObject->DriverStart);
	end = start + end;
	
	DbgPrint("[-] IAT : 0x%x - 0x%x\n", start, end);
	
	for(i=start; i<end; i=i+4)
	{
		if(*(PULONG)i != 0x0)
		{
			if(*(PULONG)i == TrueZwQuerySystemInformation)
			{
				DbgPrint("[-] Found ZwQuerySystemInformation addr at 0x%x, overwriting with 0x%x\n", i, &MyZwQuerySystemInformation);
				*(PULONG)i = &MyZwQuerySystemInformation;
			}
		}
	}
	
	DbgPrint("[-] ZwQuerySystemInformation(0,0,0,0)\n");
	ret=ZwQuerySystemInformation(0,0,0,0);
	DbgPrint("[-] Return value : 0x%x\n", ret);
    
	DbgPrint("--- HOOK IAT DRIVER ENTRY END ---\n");
    return STATUS_SUCCESS;
}
