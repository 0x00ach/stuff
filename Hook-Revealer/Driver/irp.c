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


VOID findIrpHooks(PWSTR base, PCHAR report, ULONG size)
{
	OBJECT_ATTRIBUTES atr;
	UNICODE_STRING dir_name;
	HANDLE dir;
	BYTE buff[3000];
	ULONG idx, len;
	POBJECT_NAMETYPE_INFO p;
	// DbgPrint("fingIrpHooks\n");
	RtlInitUnicodeString(&dir_name, base);
	InitializeObjectAttributes(&atr, &dir_name, OBJ_CASE_INSENSITIVE, NULL, NULL);
	ZwOpenDirectoryObject(&dir, DIRECTORY_QUERY, &atr);
	ZwQueryDirectoryObject(dir, buff, sizeof(buff), TRUE, TRUE, &idx, &len);
	
	do
	{
		p = (POBJECT_NAMETYPE_INFO)buff;
		findIrpHookForDevice(p->ObjectName, dir_name, report, size);
	}
	while(ZwQueryDirectoryObject(dir, buff, sizeof(buff), TRUE, FALSE, &idx, &len) == STATUS_SUCCESS);
}

VOID findIrpHookForDevice(UNICODE_STRING namew, UNICODE_STRING base, PCHAR report, ULONG size)
{
	PDRIVER_OBJECT driverobj;
	UNICODE_STRING name;
	USHORT err = 0;
	PWSTR temp_name[260];
	ULONG i, baseCode, endCode;
	CHAR temp[256];
	
	// DbgPrint("findIrpHookForDevice\n");
	RtlZeroMemory(temp_name,260);
	if(RtlStringCbCatW(temp_name, 260*sizeof(WCHAR), base.Buffer) != STATUS_SUCCESS)
	{
		DbgPrint(" RtlStringCbCatW error - 1\n");
		return;
	}
	if(RtlStringCbCatW(temp_name, 260*sizeof(WCHAR), L"\\") != STATUS_SUCCESS)
	{
		DbgPrint(" RtlStringCbCatW error - 2\n");
		return;
	}
	if(RtlStringCbCatW(temp_name, 260*sizeof(WCHAR), namew.Buffer) != STATUS_SUCCESS)
	{
		DbgPrint(" RtlStringCbCatW error - 3\n");
		return;
	}
	
	RtlInitUnicodeString(&name, temp_name);
	
	if(ObReferenceObjectByName(&name, 0, NULL, 0, *IoDriverObjectType, KernelMode, NULL, &driverobj)!=STATUS_SUCCESS)
	{
		DbgPrint(" %S not found.\n", name.Buffer);
		return;
	}
	ObDereferenceObject(driverobj);
	
	baseCode = (ULONG)driverobj->DriverStart;
	endCode = driverobj->DriverSize + baseCode;
	// DbgPrint("Driver : %S (0x%x / 0x%x)\n", namew.Buffer, baseCode, endCode);
	
	for(i = 0 ; i < IRP_MJ_MAXIMUM_FUNCTION ; i++)
	{
		if((driverobj->MajorFunction[i] > endCode || driverobj->MajorFunction[i] < baseCode) && driverobj->MajorFunction[i]!=IopInvalidDeviceRequest)
		{
			if(RtlStringCbPrintfA(temp, 256*sizeof(CHAR), "260|r0|||%S #%i IRP entry|%s.0x%x\n", namew.Buffer, i, whosThisAddr(driverobj->MajorFunction[i]), driverobj->MajorFunction[i])==STATUS_SUCCESS)
			{
				if(RtlStringCchCatA(report, size, temp) != STATUS_SUCCESS)
				{
						DbgPrint("Error : RtlStringCbVPrintf\n");
						return;
				}
			}
			else
			{
				DbgPrint("Error : RtlStringCbVPrintf\n");
				return;
			}
		}
	}
}
