#ifndef __IMPORTS_H__
#define __IMPORTS_H__

#include <ntddk.h>
#include <ntstrsafe.h>

//################################ NT STRUCTS IMPORTS ################################
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
} IDTINFO, *PIDTINFO, IDTR, *PIDTR;
typedef struct _INTTERUPT_STACK
{
    ULONG InterruptReturnAddress;
    ULONG SavedCS;
    ULONG SavedFlags;
    ULONG FunctionReturnAddress;
    ULONG Argument;
}INTTERUPT_STACK, *PINTTERUPT_STACK;
#pragma pack(1)
typedef struct _IDTENTRY
{
	USHORT LowOffset;
	USHORT selector;
	UCHAR un1:5;
	UCHAR zeroes:3;
	UCHAR gateType:5;
	UCHAR DPL:2;
	UCHAR P:1;
	USHORT HighOffset;
} IDTENTRY, *PIDTENTRY, IDT_DESCRIPTOR, *PIDT_DESCRIPTOR;
#pragma pack()
#pragma pack(1)
typedef struct ServiceDescriptorEntry {
unsigned int *ServiceTableBase;
unsigned int *ServiceCounterTableBase;
unsigned int NumberOfServices;
unsigned char *ParamTableBase;
} SSDT_Entry;
#pragma pack()


//################################ NT FUNCTION IMPORTS ################################
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

#endif __IMPORTS_H__