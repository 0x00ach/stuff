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
#ifndef __ROOTKITDETECT_H__
#define __ROOTKITDETECT_H__

#include <ntddk.h>
#include <ntstrsafe.h>


//################################ DEFINES ################################
// Device type           -- in the "User Defined" range."
#define SIOCTL_TYPE 40000

//well...
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
#define IOCTL_DETECT_HOOK\
    CTL_CODE( SIOCTL_TYPE, 0x901, METHOD_BUFFERED, FILE_READ_DATA|FILE_WRITE_DATA)
	
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

// undocumented structure ...
typedef struct _MODULE_ENTRY {
	LIST_ENTRY link;		// Flink, Blink
	UCHAR unknown1[16];
	ULONG imageBase;
	ULONG entryPoint;
	ULONG imageSize;
	UNICODE_STRING drvPath;
	UNICODE_STRING drvName;
	//...
} MODULE_ENTRY, *PMODULE_ENTRY;
typedef struct _OBJECT_NAMETYPE_INFO 
{
  UNICODE_STRING ObjectName;
  UNICODE_STRING ObjectType;
} OBJECT_NAMETYPE_INFO, *POBJECT_NAMETYPE_INFO;   
typedef struct _SYSTEM_MODULE_INFORMATION {
  ULONG                ModulesCount;
  SYSTEM_MODULE        Modules[0];
} SYSTEM_MODULE_INFORMATION, *PSYSTEM_MODULE_INFORMATION;
typedef struct _IMAGE_IMPORT_DESCRIPTOR {
    union {
        DWORD   Characteristics;            // 0 for terminating null import descriptor
        DWORD   OriginalFirstThunk;         // RVA to original unbound IAT (PIMAGE_THUNK_DATA)
    };
    DWORD   TimeDateStamp;                  // 0 if not bound,
                                            // -1 if bound, and real date\time stamp
                                            //     in IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT (new BIND)
                                            // O.W. date/time stamp of DLL bound to (Old BIND)

    DWORD   ForwarderChain;                 // -1 if no forwarders
    DWORD   Name;
    DWORD   FirstThunk;                     // RVA to IAT (if bound this IAT has actual addresses)
} IMAGE_IMPORT_DESCRIPTOR;
typedef IMAGE_IMPORT_DESCRIPTOR UNALIGNED *PIMAGE_IMPORT_DESCRIPTOR;
typedef struct _IDTINFO
{
	USHORT IDTLimit;
	USHORT LowIDTbase;
	USHORT HighIDTbase;
} IDTINFO, *PIDTINFO;
#pragma pack(1)
typedef struct _IDTENTRY
{
	USHORT LowOffset;
	USHORT selector;
	UCHAR unused_lo;
	UCHAR unused_hi:5;
	UCHAR DPL:2;
	UCHAR P:1;
	USHORT HighOffset;
} IDTENTRY, *PIDTENTRY;
#pragma pack()
#pragma pack(1)
typedef struct ServiceDescriptorEntry {
unsigned int *ServiceTableBase;
unsigned int *ServiceCounterTableBase;
unsigned int NumberOfServices;
unsigned char *ParamTableBase;
} SSDT_Entry;
#pragma pack()

//################################ IMPORTS ################################

NTSYSAPI
NTSTATUS
NTAPI ZwQuerySystemInformation(
IN ULONG SystemInformationClass,
			IN PVOID SystemInformation,
			IN ULONG SystemInformationLength,
			OUT PULONG ReturnLength);
NTSTATUS
__stdcall
ObReferenceObjectByName (
    __in PUNICODE_STRING ObjectName,
    __in ULONG Attributes,
    __in_opt PACCESS_STATE AccessState,
    __in_opt ACCESS_MASK DesiredAccess,
    __in POBJECT_TYPE ObjectType,
    __in KPROCESSOR_MODE AccessMode,
    __inout_opt PVOID ParseContext,
    __out PVOID *Object
);

NTSYSAPI
NTSTATUS
NTAPI ZwQueryDirectoryObject(
  __in       HANDLE DirectoryHandle,
  __out_opt  PVOID Buffer,
  __in       ULONG Length,
  __in       BOOLEAN ReturnSingleEntry,
  __in       BOOLEAN RestartScan,
  __inout    PULONG Context,
  __out_opt  PULONG ReturnLength
);

NTSYSAPI
NTSTATUS
NTAPI ZwOpenDirectoryObject(
  __out  PHANDLE DirectoryHandle,
  __in   ACCESS_MASK DesiredAccess,
  __in   POBJECT_ATTRIBUTES ObjectAttributes
);

NTKERNELAPI
KAFFINITY
NTAPI
KeSetAffinityThread(
	PKTHREAD Thread,
	KAFFINITY Affinity
);


//récupération de la SSDT de ntoskernel.exe
__declspec(dllimport) SSDT_Entry KeServiceDescriptorTable;
__declspec(dllimport) POBJECT_TYPE *IoDriverObjectType; //type exporté par le noyau

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

// Driver functions
NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegistryPath);
DRIVER_UNLOAD unload;
VOID unload(PDRIVER_OBJECT pDriverObject);

// functions
ULONG isAddrIntoModule(ULONG funcAddr, PCHAR modName);
PCHAR whosThisAddr(ULONG funcAddr);

// analysis
VOID startAnalysis(PCHAR report, PCHAR size);
// modules analysis
VOID listLoadedModules(PCHAR report, ULONG size, PULONG pulModuleList);
VOID module_analysis(PCHAR report, ULONG size, PCHAR modName, ULONG baseAddr, ULONG endAddr);
// Hooks detections global functions
VOID eatParsing(PCHAR report, ULONG size, PCHAR modName, ULONG baseAddr, ULONG endAddr, ULONG eatAddr);
VOID findIdtHooks(PCHAR report, ULONG size, ULONG baseKrnl, ULONG endKrnl);
VOID findIrpHooks(PWSTR base, PCHAR report, ULONG size);
VOID findIatHook(PCHAR report, ULONG size, PCHAR name, ULONG baseAddr, ULONG endAddr, ULONG iatAddr, ULONG iatSize);
// Specifical hook detection
VOID findIrpHookForDevice(UNICODE_STRING namew, UNICODE_STRING base, PCHAR report, ULONG size);
VOID findInlineHooks(PCHAR report, ULONG size, PCHAR modName, PCHAR funcName, ULONG funcAddr, ULONG base, ULONG end);
VOID findSYSENTERHook(PCHAR report, ULONG size, ULONG kernelBase, ULONG kernelEnd);
VOID findSSDTHooks(PCHAR report, ULONG size, ULONG kernelBase, ULONG kernelEnd);
/*
	TODO :
	void isDriverIatHooked();
		parcoure l'IAT du driver
		pour chaque entrée
			est-ce qu'on est bien dans la plage du driver ?
				tester début fonction
	
*/

#endif __ROOTKITDETECT_H__
