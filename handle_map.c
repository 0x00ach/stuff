#include <Windows.h>
#include <TlHelp32.h>
#include <stdio.h>


#define SystemHandleInformation         16
#define ObjectBasicInformation          0
#define ObjectNameInformation           1
#define ObjectTypeInformation           2
#define ObjectAllTypesInformation 3
#define ObjectHandleInformation 4

 

typedef struct _UNICODE_STRING {
	USHORT  Length;
	USHORT  MaximumLength;
	PWSTR   Buffer;
} UNICODE_STRING, *PUNICODE_STRING;
typedef struct _SYSTEM_HANDLE
{
	ULONG       ProcessId;
	BYTE        ObjectTypeNumber;
	BYTE        Flags;
	USHORT      Handle;
	PVOID       Object;
	ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE, *PSYSTEM_HANDLE;

typedef struct _SYSTEM_HANDLE_INFORMATION
{
	ULONG         HandleCount;
	SYSTEM_HANDLE Handles[1];
} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;


typedef enum _POOL_TYPE
{
	NonPagedPool,
	PagedPool,
	NonPagedPoolMustSucceed,
	DontUseThisType,
	NonPagedPoolCacheAligned,
	PagedPoolCacheAligned,
	NonPagedPoolCacheAlignedMustS
} POOL_TYPE, *PPOOL_TYPE;
typedef struct _OBJECT_TYPE_INFORMATION
{
	UNICODE_STRING  Name;
	ULONG           TotalNumberOfObjects;
	ULONG           TotalNumberOfHandles;
	ULONG           TotalPagedPoolUsage;
	ULONG           TotalNonPagedPoolUsage;
	ULONG           TotalNamePoolUsage;
	ULONG           TotalHandleTableUsage;
	ULONG           HighWaterNumberOfObjects;
	ULONG           HighWaterNumberOfHandles;
	ULONG           HighWaterPagedPoolUsage;
	ULONG           HighWaterNonPagedPoolUsage;
	ULONG           HighWaterNamePoolUsage;
	ULONG           HighWaterHandleTableUsage;
	ULONG           InvalidAttributes;
	GENERIC_MAPPING GenericMapping;
	ULONG           ValidAccess;
	BOOLEAN         SecurityRequired;
	BOOLEAN         MaintainHandleCount;
	USHORT          MaintainTypeList;
	POOL_TYPE       PoolType;
	ULONG           PagedPoolUsage;
	ULONG           NonPagedPoolUsage;
} OBJECT_TYPE_INFORMATION, *POBJECT_TYPE_INFORMATION;


typedef struct _PUBLIC_OBJECT_BASIC_INFORMATION {
	ULONG Attributes;
	ACCESS_MASK GrantedAccess;
	ULONG HandleCount;
	ULONG PointerCount;
	ULONG 	PagedPoolCharge;
	ULONG 	NonPagedPoolCharge;
	ULONG 	Reserved[3];
	ULONG 	NameInfoSize;
	ULONG 	TypeInfoSize;
	ULONG 	SecurityDescriptorSize;
	LARGE_INTEGER 	CreationTime;
} PUBLIC_OBJECT_BASIC_INFORMATION, *PPUBLIC_OBJECT_BASIC_INFORMATION;

typedef NTSTATUS(NTAPI *_NtQueryObject)(
	HANDLE ObjectHandle,
	ULONG  ObjectInformationClass,
	PVOID  ObjectInformation,
	ULONG  ObjectInformationLength,
	PULONG ReturnLength
	);
typedef NTSTATUS(WINAPI *_NtQuerySystemInformation)(ULONG SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength
	);

typedef struct _ProcessList {
	ULONG pid;
	_ProcessList* next;
}ProcessList, *pProcessList;
typedef struct _Process {
	ULONG pid;
	PWCHAR processName;
	_Process* next;
}Process, *pProcess;
typedef struct _ObjectDefList {
	PVOID objectKernelAddr;
	pProcessList processes;
	ULONG processessCount;
	_ObjectDefList* next;
}ObjectDefList, *pObjectDefList;

pObjectDefList pObjects = NULL;
pProcess processList = NULL;
BOOL insertObject(PVOID objAddr, ULONG pid) {
	pObjectDefList pObjWalk;
	pProcessList pProc;

	pObjWalk = pObjects;
	while (pObjWalk != NULL) {
		if (pObjWalk->objectKernelAddr == objAddr) {
			pProc = pObjWalk->processes;
			while (pProc != NULL) {
				if (pProc->pid == pid)
					return TRUE;
				pProc = pProc->next;
			}
			pProc = (pProcessList)HeapAlloc(GetProcessHeap(), 0, sizeof(pProcessList));
			pProc->pid = pid;
			pProc->next = pObjWalk->processes;
			pObjWalk->processes = pProc;
			pObjWalk->processessCount = pObjWalk->processessCount+1;
			return TRUE;
		}
		pObjWalk = pObjWalk->next;
	}

	pObjWalk = (pObjectDefList)HeapAlloc(GetProcessHeap(), 0, sizeof(ObjectDefList));
	pProc = (pProcessList)HeapAlloc(GetProcessHeap(), 0, sizeof(pProcessList));

	pProc->pid = pid;
	pProc->next = NULL;
	pObjWalk->processessCount = 1;
	pObjWalk->processes = pProc;
	pObjWalk->objectKernelAddr = objAddr;
	pObjWalk->next = pObjects;
	pObjects = pObjWalk;
	return TRUE;
}
BOOL buildProcessList() {
	HANDLE hSnap;
	PROCESSENTRY32W ppe = { 0 };
	BOOL stat;
	pProcess proc;
	PWCHAR lol;
	ppe.dwSize = sizeof(ppe);
	hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	stat = Process32First(hSnap, &ppe);
	while (stat == TRUE) {
		proc = (pProcess)HeapAlloc(GetProcessHeap(), 0, sizeof(Process));
		lol = (PWCHAR)HeapAlloc(GetProcessHeap(), 0, sizeof(WCHAR)*(wcslen(ppe.szExeFile) + 1));
		memcpy(lol, ppe.szExeFile, sizeof(WCHAR)*(wcslen(ppe.szExeFile) + 1));
		proc->pid = ppe.th32ProcessID;
		proc->processName = lol;
		proc->next = processList;
		processList = proc;
		stat = Process32Next(hSnap, &ppe);
	}
	// don't close the snapshot ;)
	return TRUE;
}
PWCHAR pidToProcessName(ULONG pid) {
	pProcess proc = processList;
	while (proc != NULL) {
		if (proc->pid == pid)
			return proc->processName;
		proc = proc->next;
	}
	return L"Unknown";
}


int __cdecl main(int argc, char** argv) {
	DWORD dwSize = 60000;
	ULONG stat, i;
	_NtQuerySystemInformation NtQuerySystemInformation = NULL;
	PSYSTEM_HANDLE_INFORMATION pSystemHandleInformation = (PSYSTEM_HANDLE_INFORMATION)HeapAlloc(GetProcessHeap(), 0, 60000);
	pObjectDefList pObj;
	pProcessList pProc;

	printf("[+] Building handles list\n");
	NtQuerySystemInformation = (_NtQuerySystemInformation)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtQuerySystemInformation");
	stat = NtQuerySystemInformation(SystemHandleInformation,
		pSystemHandleInformation,
		dwSize,
		&dwSize);
	while (stat == 0xC0000004)	{
		dwSize = dwSize * 2;
		HeapFree(GetProcessHeap(), 0, pSystemHandleInformation);
		pSystemHandleInformation = (PSYSTEM_HANDLE_INFORMATION)HeapAlloc(GetProcessHeap(), 0, dwSize);
		stat = NtQuerySystemInformation(SystemHandleInformation, pSystemHandleInformation, dwSize, &dwSize);
	}
	buildProcessList();

	if (stat == 0) {
		for (i = 0; i < pSystemHandleInformation->HandleCount; i++)
			insertObject(pSystemHandleInformation->Handles[i].Object, pSystemHandleInformation->Handles[i].ProcessId);
	}
	else
		printf("NtQuerySystemInformation returned %x\n", stat);

	printf("[+] Shared handles map\n");
	pObj = pObjects;
	while (pObj != NULL) {
		if (pObj->processessCount > 1) {
			printf("%p\n", pObj->objectKernelAddr);
			pProc = pObj->processes;
			while (pProc != NULL) {
				printf("\t%S\n", pidToProcessName(pProc->pid));
				pProc = pProc->next;
			}
		}
		pObj = pObj->next;
	}

	system("pause");
 
}
