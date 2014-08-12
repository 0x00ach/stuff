#include "main.h"

VOID unload(PDRIVER_OBJECT pDriverObject)
{
	restoreIDT();
	DbgPrint("- IDT - Driver unloaded\n");
}

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegistryPath)
{
	DbgPrint("- IDT - DriverEntry\n");
	
	
	DbgPrint("- IDT - DE TID %x\n", PsGetCurrentThreadId());

    pDriverObject->DriverUnload = unload;
    pDriverObject->MajorFunction[IRP_MJ_CREATE] = Fonction_IRP_MJ_CREATE;
    pDriverObject->MajorFunction[IRP_MJ_CLOSE] = Fonction_IRP_MJ_CLOSE;
    pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = Fonction_IRP_DEVICE_CONTROL;
	
	hookIDT();

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
    return STATUS_SUCCESS;
}
