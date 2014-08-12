#ifndef __MAIN_H__
#define __MAIN_H__

#include <ntddk.h>
#include <ntstrsafe.h>
#include "imports.h"

//################################ DEFINES ################################
typedef unsigned long DWORD;
typedef unsigned short WORD;
typedef unsigned char BYTE;
typedef DWORD *PDWORD;
typedef WORD *PWORD;
typedef BYTE *PBYTE;

//################################ GLOBALS ################################
//the kernel does not export this function...
ULONG IopInvalidDeviceRequest;
PSYSTEM_MODULE_INFORMATION modulesInMemory;

//################################ FUNCTIONS ################################
//IRP dispatchers
__drv_dispatchType(IRP_MJ_DEVICE_CONTROL) 
DRIVER_DISPATCH Fonction_IRP_DEVICE_CONTROL;
__drv_dispatchType(IRP_MJ_CLOSE) 
DRIVER_DISPATCH Fonction_IRP_MJ_CLOSE;
__drv_dispatchType(IRP_MJ_CREATE) 
DRIVER_DISPATCH Fonction_IRP_MJ_CREATE;
NTSTATUS Fonction_IRP_DEVICE_CONTROL(PDEVICE_OBJECT DeviceObject,PIRP Irp);
NTSTATUS Fonction_IRP_MJ_CLOSE(PDEVICE_OBJECT DeviceObject,PIRP Irp);
NTSTATUS Fonction_IRP_MJ_CREATE(PDEVICE_OBJECT DeviceObject,PIRP Irp);

//IDT
VOID hookIDT();
VOID restoreIDT();
int3Handler();
ULONG __stdcall int3Check(PINTTERUPT_STACK savedstack);
int6Handler();
ULONG __stdcall int6Check(PINTTERUPT_STACK savedstack);

// Driver functions
NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegistryPath);
DRIVER_UNLOAD unload;
VOID unload(PDRIVER_OBJECT pDriverObject);

#endif __MAIN_H__