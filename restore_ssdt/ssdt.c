#include <ntddk.h>
#include <ntstrsafe.h>

#define IMAGE_DOS_SIGNATURE             0x5A4D      // MZ
#define IMAGE_NT_SIGNATURE              0x00004550  // PE00
#define SIZE_OF_SECTION_DEF				0x28
#define IOCTL_SSDT_UNHOOK\
    CTL_CODE( SIOCTL_TYPE, 0x903, METHOD_BUFFERED, FILE_READ_DATA|FILE_WRITE_DATA)

typedef unsigned long DWORD;
typedef unsigned short WORD;
typedef unsigned char BYTE;
typedef DWORD *PDWORD;
typedef WORD *PWORD;
typedef BYTE *PBYTE;

#pragma pack(1)
typedef struct ServiceDescriptorEntry {
unsigned int *ServiceTableBase;
unsigned int *ServiceCounterTableBase;
unsigned int NumberOfServices;
unsigned char *ParamTableBase;
} SSDT_Entry;
#pragma pack()

//SSDT import
__declspec(dllimport) SSDT_Entry KeServiceDescriptorTable;

//functions
NTSTATUS ssdt_full_restore();
NTSTATUS Fonction_IRP_DEVICE_CONTROL(PDEVICE_OBJECT DeviceObject,PIRP Irp);
NTSTATUS Fonction_IRP_MJ_CLOSE(PDEVICE_OBJECT DeviceObject,PIRP Irp);
NTSTATUS Fonction_IRP_MJ_CREATE(PDEVICE_OBJECT DeviceObject,PIRP Irp);



NTSYSAPI
NTSTATUS
NTAPI ZwQuerySystemInformation(
IN ULONG SystemInformationClass,
			IN PVOID SystemInformation,
			IN ULONG SystemInformationLength,
			OUT PULONG ReturnLength);

NTSYSAPI
NTSTATUS
 ZwUnloadDriver(
  IN PUNICODE_STRING DriverServiceName
);

NTSYSAPI
NTSTATUS
NTAPI ZwReadFile(
  IN      HANDLE FileHandle,
  IN  HANDLE Event,
  IN  PIO_APC_ROUTINE ApcRoutine,
  IN  PVOID ApcContext,
  OUT     PIO_STATUS_BLOCK IoStatusBlock,
  OUT     PVOID Buffer,
  IN      ULONG Length,
  IN  PLARGE_INTEGER ByteOffset,
  IN  PULONG Key
);

NTSYSAPI
NTSTATUS
NTAPI ZwOpenFile(
  OUT  PHANDLE FileHandle,
  IN   ACCESS_MASK DesiredAccess,
  IN   POBJECT_ATTRIBUTES ObjectAttributes,
  OUT  PIO_STATUS_BLOCK IoStatusBlock,
  IN   ULONG ShareAccess,
  IN   ULONG OpenOptions
);

typedef ULONG  ACCESS_MASK;
typedef struct _SYSTEM_MODULE {
  ULONG                Reserved1;
  ULONG                Reserved2;
  ULONG                ImageBaseAddress;
  ULONG                ImageSize;
  ULONG                Flags;
  USHORT                 Id;
  USHORT                 Rank;
  USHORT                 w018;
  USHORT                 NameOffset;
  UCHAR                 Name[MAXIMUM_FILENAME_LENGTH];
} SYSTEM_MODULE, *PSYSTEM_MODULE;

typedef struct _SYSTEM_MODULE_INFORMATION {
  ULONG                ModulesCount;
  SYSTEM_MODULE        Modules[0];
} SYSTEM_MODULE_INFORMATION, *PSYSTEM_MODULE_INFORMATION;

//CR0 trick
void cro()
{
	__asm
	{
	push eax
	mov  eax, CR0 
	and  eax, 0FFFEFFFFh 
	mov  CR0, eax 
	pop  eax
	}
}
void uncro()
{
	__asm
	{
	push eax
	mov  eax, CR0
	or   eax, NOT 0FFFEFFFFh 
	mov  CR0, eax
	pop  eax 
	}
}



/**
	
	SSDT restoration p0c: find SSDT hooks and restore original values using the original kernel's image.

	- get the kernel & SSDT base address
	- open the kernel image file
	- find the SSDT address in the file : 
		- find the section exporting the SSDT
		- diff between RVA in memory and in the image file
	- for each SSDT entry not pointing on the kernel's memory range
	---> find the ssdt entry in the binary file, calculate the address
	---> diff and verify that the address is in the kernel's memory range
	---> restore

	@00_ach
*/
NTSTATUS ssdt_full_restore()
{
	// Zw* calls
	ULONG ulNeededSize=0;
	IO_STATUS_BLOCK statusBlck;
	OBJECT_ATTRIBUTES objAttr;
	NTSTATUS ret;
	
	// listing modules in the kernel
	PULONG pulModuleList;
	PSYSTEM_MODULE_INFORMATION pModList;
	PSYSTEM_MODULE pKernelInfo;
	
	// ZwRead, ZwOpen, etc.
	UNICODE_STRING kernelImagePath, kern2, kern1;
	ANSI_STRING kernelImagePathA;
	HANDLE fileHandle;
	WCHAR tempChar[260];
	
	// MEMORY
	ULONG kernelBase, kernelEnd;		// kernel memory region
	ULONG imageBaseInMem;			// kernel memory address defined in its PE header
	
	//SSDT (file)
	ULONG nbEntries, cpt;			
	LARGE_INTEGER kiservtableOffset;	// SSDT offset in the binary file
	ULONG offst;				// offset between in memory and raw image file
	ULONG entryRead;
	//SSDT (memory)
	ULONG ssdtOffsetMem;
	
	//PE HEADER
	BOOLEAN peCorrect;
	ULONG peOffset;	
	USHORT nbSections;	
	ULONG offsetOfSections;
	PUCHAR allo;
	PUCHAR peHeaderPtr;
	
	//SECTIONS DEFINITIONS
	ULONG i;	
	// section information
	ULONG baseSectMem;
	ULONG baseSectRaw;
	ULONG endSectMem;
	
	
	//reading loaded modules
	ZwQuerySystemInformation(11, &ulNeededSize, 0, &ulNeededSize);
	pulModuleList = ExAllocatePoolWithTag(PagedPool, ulNeededSize, 'mlst');
	ret = ZwQuerySystemInformation(11, pulModuleList, ulNeededSize, 0);
	if(ret != STATUS_SUCCESS)
	{
		DbgPrint("[!] ZwQuerySysInfo failed!\n");
		return 0;
	}
	
	// retrieving the kernel memory range
	pModList=(PSYSTEM_MODULE_INFORMATION) pulModuleList;
	pKernelInfo=&pModList->Modules[0];
	kernelBase=(ULONG)pKernelInfo->ImageBaseAddress;
	kernelEnd=kernelBase+pKernelInfo->ImageSize;
	// DbgPrint("[+] Kernel memory range : 0x%x - 0x%x\n", kernelBase, kernelEnd);
	
	// SSDT entries
	nbEntries=KeServiceDescriptorTable.NumberOfServices;
	
	// 260 == MAX_PATH
	kernelImagePath.Buffer=tempChar;
	kernelImagePath.Length = 0;
	kernelImagePath.MaximumLength = 260*sizeof(WCHAR);
	
	// must be in SystemRoot\system32
	RtlInitUnicodeString(&kern1, L"\\SystemRoot\\System32\\");
	
	//ANSI string init
	RtlInitAnsiString(&kernelImagePathA,pKernelInfo->Name+pKernelInfo->NameOffset);
	
	// to unicode
	ret = RtlAnsiStringToUnicodeString(&kern2, &kernelImagePathA, TRUE);
	
	// find the "ImageBase" address of the kernel in its PE header
	imageBaseInMem = *(PULONG)(kernelBase + *(PULONG)(kernelBase + 0x3C) + 0x34);

	// SSDT RVA
	ssdtOffsetMem = (ULONG)KeServiceDescriptorTable.ServiceTableBase - kernelBase;

	// DbgPrint("[+] SSDT in memory = 0x%x\n", (ULONG)KeServiceDescriptorTable.ServiceTableBase);
	// DbgPrint("[+] RVA SSDT in memory = 0x%x\n", ssdtOffsetMem);
	
	if(!ret)
	{
		// concat
		ret = RtlUnicodeStringCat(&kernelImagePath, &kern1);
		ret = RtlUnicodeStringCat(&kernelImagePath, &kern2);
		
		if(!ret)
		{
			InitializeObjectAttributes( &objAttr, &kernelImagePath, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);
			// kernel image file
			ret = ZwOpenFile(&fileHandle, FILE_READ_DATA, &objAttr, &statusBlck, FILE_SHARE_READ, FILE_SYNCHRONOUS_IO_NONALERT);
			
			if(!ret)
			{
				allo = ExAllocatePoolWithTag(PagedPool, 0x1000, 'yaha');
				if(allo != NULL)
				{
					peHeaderPtr = allo;
					// reading PE header
					ret = ZwReadFile(fileHandle, NULL, NULL, NULL, &statusBlck, peHeaderPtr, 0x1000, 0, NULL);
					peCorrect = FALSE;
					if(!ret)
					{
						offst = 0;
						// "MZ"
						if(*(PUSHORT)peHeaderPtr == IMAGE_DOS_SIGNATURE)
						{
							// PE offset
							peOffset = *(PULONG)(peHeaderPtr + 0x3C);
							
							if(peOffset < 0xF00)
							{
								peHeaderPtr = (PUCHAR)(peHeaderPtr + peOffset);
								// "PE"
								if(*(PULONG)peHeaderPtr == IMAGE_NT_SIGNATURE)
								{
									offsetOfSections = *(PUSHORT)(peHeaderPtr + 0x14);		// SizeOfOptionalHeaders
									offsetOfSections = offsetOfSections + 0x18;		// skip PE header
									
									// sections count
									nbSections =*(PUSHORT)(peHeaderPtr + 6);
									peHeaderPtr = peHeaderPtr + offsetOfSections;
									
									if((peOffset + nbSections * SIZE_OF_SECTION_DEF) < 0x1000)
									{
										// reading sections
										for (i=0; i<nbSections; i++)
										{
											//DbgPrint("[+] Section %d : %s\n", i, peHeaderPtr);
											// find section exporting SSDT
											baseSectMem = *((PULONG)peHeaderPtr + 0x3);
											endSectMem = baseSectMem + *((PULONG)peHeaderPtr + 0x2);
											baseSectRaw = *((PULONG)peHeaderPtr + 0x5);
											
											//DbgPrint("[+] bsecmem : 0x%x, esecmem : 0x%x, bsecraw : 0x%x\n", baseSectMem, endSectMem, baseSectRaw);
											// is SSDT in this section ?
											if(ssdtOffsetMem > baseSectMem && ssdtOffsetMem < endSectMem)
											{
												// get the offset between disk and memory images
												offst = baseSectMem - baseSectRaw;
												peCorrect = TRUE;
												DbgPrint("[+] Section found, offset: 0x%x\n", offst);
												break;
											}
											//next section
											peHeaderPtr = peHeaderPtr + 0x28;
										}
									}
								}
							}
						}
						
						// found !
						if(peCorrect)
						{
							// for each SSDT entry
							for(cpt=0; cpt<nbEntries; cpt++)
							{
								if(KeServiceDescriptorTable.ServiceTableBase[cpt] < kernelBase || KeServiceDescriptorTable.ServiceTableBase[cpt] > kernelEnd)
								{
									// we're out of the kernel's memory range => hook!
									// offset : in memory RVA + cpt *4 (car ULONG[] ) - offset between memory and disk
									kiservtableOffset.LowPart=ssdtOffsetMem + (cpt*4) - offst;
									kiservtableOffset.HighPart = 0;
									
									// read the original value
									ret = ZwReadFile(fileHandle, NULL, NULL, NULL, &statusBlck, &entryRead, 4, &kiservtableOffset, NULL);
									if(!ret)
									{
										// DbgPrint("[+] Entry =  0x%x - 0x%x + 0x%x\n", entryRead, imageBaseInMem, kernelBase);
										// convert to avoid relocation issues
										entryRead = entryRead - imageBaseInMem + kernelBase;
										
										if(entryRead < kernelEnd && entryRead > kernelBase)
										{
											// Restore
											DbgPrint("[+] Restoring %x entry, from 0x%x to 0x%x\n", cpt, KeServiceDescriptorTable.ServiceTableBase[cpt], entryRead);
											cro();
											KeServiceDescriptorTable.ServiceTableBase[cpt]  = entryRead;
											uncro();
										}
									}
								}
							}
						}
					}
					if(peHeaderPtr != NULL)
						ExFreePool(allo);
						
				}
				ZwClose(fileHandle);
			}
		}
	}
	return STATUS_SUCCESS;
}


VOID unload(PDRIVER_OBJECT pDriverObject)
{
	UNICODE_STRING NomLien;
	RtlInitUnicodeString(&NomLien,L"\\DosDevices\\ssdtrestore");
	
	IoDeleteSymbolicLink(&NomLien);
	if(pDriverObject!=NULL)
		IoDeleteDevice(pDriverObject->DeviceObject);
	
    DbgPrint("[+] Driver unloaded.\n");
}

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegistryPath)
{
    UNICODE_STRING NomInterface,NomLien;
	DEVICE_OBJECT ptrInterface;
	
	DbgPrint("[+] Driver loaded.\n");

    RtlInitUnicodeString(&NomInterface,L"\\Device\\ssdtrestore");

    IoCreateDevice(pDriverObject,0,&NomInterface,FILE_DEVICE_UNKNOWN,FILE_DEVICE_UNKNOWN,FALSE,&ptrInterface);
    pDriverObject->DriverUnload = unload;
    pDriverObject->MajorFunction[IRP_MJ_CREATE] = Fonction_IRP_MJ_CREATE;
    pDriverObject->MajorFunction[IRP_MJ_CLOSE] = Fonction_IRP_MJ_CLOSE;
    pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = Fonction_IRP_DEVICE_CONTROL;

    RtlInitUnicodeString(&NomLien,L"\\DosDevices\\ssdtrestore");
    IoCreateSymbolicLink(&NomLien,&NomInterface);

    return STATUS_SUCCESS;
	
}

NTSTATUS Fonction_IRP_MJ_CREATE(PDEVICE_OBJECT DeviceObject,PIRP Irp)
{
    return STATUS_SUCCESS;
}

NTSTATUS Fonction_IRP_MJ_CLOSE(PDEVICE_OBJECT DeviceObject,PIRP Irp)
{
    return STATUS_SUCCESS;
}

NTSTATUS Fonction_IRP_DEVICE_CONTROL(PDEVICE_OBJECT DeviceObject,PIRP Irp)
{
    PIO_STACK_LOCATION pIoStackLocation;
    PVOID pBuf = Irp->AssociatedIrp.SystemBuffer;
    PEPROCESS ptrStructProcessToHide;
    long pid, Output_Size;
    int retour;
	ULONG retfunc;
	
	PCHAR Output_Buffer =  Irp->AssociatedIrp.SystemBuffer;
	PUCHAR param;
    pIoStackLocation = IoGetCurrentIrpStackLocation(Irp);
	Output_Size  =  pIoStackLocation->Parameters.DeviceIoControl.InputBufferLength;

    switch(pIoStackLocation->Parameters.DeviceIoControl.IoControlCode)
    {
            case IOCTL_SSDT_UNHOOK :
				ssdt_full_restore();
                break;
			
			default:
				break;
    }

    Irp->IoStatus.Status = STATUS_SUCCESS;

    IoCompleteRequest(Irp,IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}
