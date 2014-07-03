#include <ntddk.h>

// Device type           -- in the "User Defined" range."
#define SIOCTL_TYPE 40000
typedef unsigned long DWORD;
typedef unsigned short WORD;
typedef unsigned char BYTE;
typedef DWORD *PDWORD;
typedef WORD *PWORD;
typedef BYTE *PBYTE;

// The IOCTL function codes from 0x800 to 0xFFF are for customer use.
// BUT... I use 0x801 and following ones in another project ;)

// METHOD BUFFERED :
// A buffer is allocated and the data is copied from this buffer. The buffer is created as the larger of the two sizes, the input or output buffer.
#define IOCTL_SSDT_UNHOOK\
    CTL_CODE( SIOCTL_TYPE, 0x903, METHOD_BUFFERED, FILE_READ_DATA|FILE_WRITE_DATA)

NTSTATUS ssdt_full_restore();
NTSTATUS Fonction_IRP_DEVICE_CONTROL(PDEVICE_OBJECT DeviceObject,PIRP Irp);
NTSTATUS Fonction_IRP_MJ_CLOSE(PDEVICE_OBJECT DeviceObject,PIRP Irp);
NTSTATUS Fonction_IRP_MJ_CREATE(PDEVICE_OBJECT DeviceObject,PIRP Irp);
	
VOID unload(PDRIVER_OBJECT pDriverObject)
{
	//must destroy objects !
	UNICODE_STRING NomLien;
	RtlInitUnicodeString(&NomLien,L"\\DosDevices\\ssdtrestore");
	
	IoDeleteSymbolicLink(&NomLien);
	if(pDriverObject!=NULL)
		IoDeleteDevice(pDriverObject->DeviceObject);
	
    DbgPrint(" [ -SSDT- ] Driver unloaded.\n");
}

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegistryPath)
{
    UNICODE_STRING NomInterface,NomLien;
	DEVICE_OBJECT ptrInterface;
	
	DbgPrint(" [ -SSDT- ] Driver loaded.\n");

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
   // DbgPrint(" [ -HOOK DETECT- ] IRP MJ CREATE received.\n");
    return STATUS_SUCCESS;
}

NTSTATUS Fonction_IRP_MJ_CLOSE(PDEVICE_OBJECT DeviceObject,PIRP Irp)
{
   // DbgPrint(" [ -HOOK DETECT- ] IRP MJ CLOSE received.\n");
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
	
    // Finish the I/O operation by simply completing the packet and returning
    // the same status as in the packet itself.
    Irp->IoStatus.Status = STATUS_SUCCESS;

    IoCompleteRequest(Irp,IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}
