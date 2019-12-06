#include <Windows.h>
#include <stdio.h>
#include <AclAPI.h>
#include <sddl.h>
#define CLOSE(x) CloseHandle(x);x=NULL;
#define LFREE(x) if(x!=NULL){LocalFree(x);x=NULL;}
#define MFREE(x) if(x!=NULL){free(x);x=NULL;}

#define ADDRIGHTSSDDL_FULL_ACCESS "(XA;;FA;;;BU; (!(1 == 1)))"
#define ADDRIGHTSSDDL_KEY_ALL_ACCESS "(XA;;KA;;;BU; (!(1 == 1)))"
BOOL AddCustomACEToSD(PSECURITY_DESCRIPTOR pOldSecurityDescriptor, PSECURITY_DESCRIPTOR* pNewSecurityDescriptor, char* NewACESDDL) {
	LPSTR sddl = NULL;
	char NewSDDL[0x1000] = { 0 };

	if (ConvertSecurityDescriptorToStringSecurityDescriptorA(
		pOldSecurityDescriptor,
		SDDL_REVISION_1,
		DACL_SECURITY_INFORMATION,
		&sddl,
		NULL) == FALSE)
		return FALSE;
	
	strcpy_s(NewSDDL, 0x1000, sddl);

	// already set ?
	if (strstr(NewSDDL, "1 == 1") == NULL) {
		if (strcat_s(NewSDDL, 0x1000, NewACESDDL) != 0)
			return FALSE;
	}

	LFREE(sddl);

	if (ConvertStringSecurityDescriptorToSecurityDescriptorA(NewSDDL,
		SDDL_REVISION_1,
		pNewSecurityDescriptor,
		NULL) == FALSE){
		printf("GetLastError: %x %s", GetLastError(), NewSDDL);
		return FALSE;
	}

	return TRUE;

}

VOID PrintSD(PSECURITY_DESCRIPTOR pSecurityDescriptor) {
	LPSTR sddl = NULL;

	ConvertSecurityDescriptorToStringSecurityDescriptorA(
		pSecurityDescriptor,
		SDDL_REVISION_1,
		DACL_SECURITY_INFORMATION,
		&sddl,
		NULL);

	printf("\tSDDL: %s\n"
		"\tSD->Revision: %d\n"
		"\tSD->Control: %x\n"
		"\tSD->Sbz1: %d\n"
		"\tSD->Dacl: %p\n"
		"\tSD->Dacl->AceCount: %d\n"
		"\tSD->Dacl->AclSize: %d\n"
		"",
		sddl,
		((PISECURITY_DESCRIPTOR_RELATIVE)pSecurityDescriptor)->Revision,
		((PISECURITY_DESCRIPTOR_RELATIVE)pSecurityDescriptor)->Control,
		((PISECURITY_DESCRIPTOR_RELATIVE)pSecurityDescriptor)->Sbz1,
		(SIZE_T)((PISECURITY_DESCRIPTOR_RELATIVE)pSecurityDescriptor)->Dacl + (SIZE_T)pSecurityDescriptor,
		((PACL)(((PISECURITY_DESCRIPTOR_RELATIVE)pSecurityDescriptor)->Dacl + (SIZE_T)pSecurityDescriptor))->AceCount,
		((PACL)(((PISECURITY_DESCRIPTOR_RELATIVE)pSecurityDescriptor)->Dacl + (SIZE_T)pSecurityDescriptor))->AclSize);
}


void setToFile(char* FileName){
	HANDLE hFile = NULL;
	ULONG dwSize = 0;
	LPSTR str = NULL;
	PACL pDacl = NULL;
	PSECURITY_DESCRIPTOR pOldSecurityDescriptor = NULL, pNewSecurityDescriptor = NULL;


	hFile = CreateFileA(FileName,                // name of the write
		GENERIC_ALL,          // open for writing
		0,                      // do not share
		NULL,                   // default security
		OPEN_EXISTING,             // create new file only
		FILE_ATTRIBUTE_NORMAL,  // normal file
		NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		printf("!!! CreateFileA failed !!!\n");
		goto fail;
	}
	
	if (GetSecurityInfo(hFile,
		SE_FILE_OBJECT,
		DACL_SECURITY_INFORMATION,
		NULL,
		NULL,
		&pDacl,
		NULL,
		&pOldSecurityDescriptor) != ERROR_SUCCESS) {
		printf("!!! GetSecurityInfo failed (1) !!!\n");
		goto fail;
	}

	printf("=== ACTUAL %s SD ===\n", FileName);
	PrintSD(pOldSecurityDescriptor);

	if (AddCustomACEToSD(pOldSecurityDescriptor, &pNewSecurityDescriptor, ADDRIGHTSSDDL_FULL_ACCESS) == FALSE) {
		printf("!!! AddCustomACEToSD failed !!!\n");
		goto fail;
	}
	LFREE(pOldSecurityDescriptor);


	printf("=== GENERATED NEW SD ===\n");
	PrintSD(pNewSecurityDescriptor);
		
	dwSize = SetSecurityInfo(hFile,
		SE_FILE_OBJECT,
		DACL_SECURITY_INFORMATION,
		NULL,
		NULL,
		(PACL)((SIZE_T)((PISECURITY_DESCRIPTOR_RELATIVE)pNewSecurityDescriptor)->Dacl + (SIZE_T)pNewSecurityDescriptor),
		NULL);
	printf("=== SetSecurityInfo returned %d ===\n", dwSize);
	CLOSE(hFile);

	hFile = CreateFileA(FileName, 
		GENERIC_READ,   
		0,                
		NULL,              
		OPEN_EXISTING,   
		FILE_ATTRIBUTE_NORMAL, 
		NULL);
	if (GetSecurityInfo(hFile,
		SE_FILE_OBJECT,
		DACL_SECURITY_INFORMATION,
		NULL,
		NULL,
		&pDacl,
		NULL,
		&pOldSecurityDescriptor) != ERROR_SUCCESS) {
		printf("!!! GetSecurityInfo failed (2) !!!\n");
		goto fail;
	}

	printf("=== NEW FILE SD ===\n");
	PrintSD(pOldSecurityDescriptor);

fail:

	CLOSE(hFile);
	LFREE(pOldSecurityDescriptor);
	LFREE(pNewSecurityDescriptor);

	return;
}

void setToReg(HKEY baseKey, char* KeyPath){

	HKEY oK;
	PSECURITY_DESCRIPTOR pNewSecurityDescriptor = NULL;
	PSECURITY_DESCRIPTOR pSecurityDescriptor = (PSECURITY_DESCRIPTOR)malloc(0x1000);
	LPSTR str = NULL;
	DWORD sz = 0x1000;
	


	if (RegOpenKeyExA(baseKey, KeyPath, 0, KEY_ALL_ACCESS, &oK) != ERROR_SUCCESS){
		printf("!!! RegOpenKeyExA failed !!!\n");
		goto fail;
	}
		
	if (RegGetKeySecurity(oK, DACL_SECURITY_INFORMATION, pSecurityDescriptor, &sz) != ERROR_SUCCESS){
		printf("!!! RegGetKeySecurity failed (1) !!!\n");
		goto fail;
	}

	printf("=== ACTUAL %s SD ===\n", KeyPath);
	PrintSD(pSecurityDescriptor);


	if (AddCustomACEToSD(pSecurityDescriptor, &pNewSecurityDescriptor, ADDRIGHTSSDDL_KEY_ALL_ACCESS) == FALSE) {
		printf("!!! AddCustomACEToSD failed !!!\n");
		goto fail;
	}

	printf("=== GENERATED NEW SD ===\n");
	PrintSD(pNewSecurityDescriptor);

	if (RegSetKeySecurity(oK, DACL_SECURITY_INFORMATION, pNewSecurityDescriptor) != ERROR_SUCCESS){
		printf("!!! RegSetKeySecurity failed !!!\n");
		goto fail;
	}

	sz = 1000;
	if (RegGetKeySecurity(oK, DACL_SECURITY_INFORMATION, pSecurityDescriptor, &sz) != ERROR_SUCCESS){
		printf("!!! RegGetKeySecurity failed (2) !!!\n");
		goto fail;
	}

	printf("=== NEW SD ===\n");
	PrintSD(pSecurityDescriptor);


fail:
	MFREE(pSecurityDescriptor);
	LFREE(pNewSecurityDescriptor);
}

int main(int argc, char** argv){
	char* target = NULL;
	if (argc <= 2) {
		printf("Usage: %s -reg|-file <path>\n"
			"e.g: -file C:\\test.txt\n"
			"e.g: -reg SOFTWARE\\Microsoft (HKLM hive)\n", argv[0]);
		return 0;

	}

	if (!_stricmp(argv[1], "-reg"))
		setToReg(HKEY_LOCAL_MACHINE, argv[2]);

	if (!_stricmp(argv[1], "-file"))
		setToFile(argv[2]);

	return 0;
}
