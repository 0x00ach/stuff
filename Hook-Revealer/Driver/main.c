// Copyright 2013 Conix Security, Adrien Chevalier
// adrien.chevalier@conix.fr
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.
#include "rootkitdetect.h"

VOID unload(PDRIVER_OBJECT pDriverObject)
{
	//must destroy objects !
	UNICODE_STRING NomLien;
	RtlInitUnicodeString(&NomLien,L"\\DosDevices\\hookrevealer");
	
	IoDeleteSymbolicLink(&NomLien);
	if(pDriverObject!=NULL)
		IoDeleteDevice(pDriverObject->DeviceObject);
	
    DbgPrint(" [ -HOOK DETECT- ] Driver unloaded.\n");
}

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegistryPath)
{
    UNICODE_STRING NomInterface,NomLien;
	DEVICE_OBJECT ptrInterface;
	
	
	DbgPrint(" [ -HOOK DETECT- ] Driver loaded.\n");
	
	
    RtlInitUnicodeString(&NomInterface,L"\\Device\\hookrevealer");

    IoCreateDevice(pDriverObject,0,&NomInterface,FILE_DEVICE_UNKNOWN,FILE_DEVICE_UNKNOWN,FALSE,&ptrInterface);
    pDriverObject->DriverUnload = unload;
    pDriverObject->MajorFunction[IRP_MJ_CREATE] = Fonction_IRP_MJ_CREATE;
    pDriverObject->MajorFunction[IRP_MJ_CLOSE] = Fonction_IRP_MJ_CLOSE;
    pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = Fonction_IRP_DEVICE_CONTROL;
	
	//IRP_MJ_QUERY_INFORMATION is not defined, so it's value must be the IopInvalidDeviceRequest address
	IopInvalidDeviceRequest = pDriverObject->MajorFunction[5];

    RtlInitUnicodeString(&NomLien,L"\\DosDevices\\hookrevealer");
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
	PCHAR Output_Buffer;

	Output_Buffer = Irp->AssociatedIrp.SystemBuffer;
    pIoStackLocation = IoGetCurrentIrpStackLocation(Irp);
	Output_Size = pIoStackLocation->Parameters.DeviceIoControl.InputBufferLength;

    switch(pIoStackLocation->Parameters.DeviceIoControl.IoControlCode)
    {
            case IOCTL_DETECT_HOOK :
				//init message
				RtlZeroMemory(Output_Buffer,Output_Size);
				//start !
				startAnalysis(Output_Buffer, Output_Size);
				//return message
				Irp->IoStatus.Information = strlen(Output_Buffer);
				
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
