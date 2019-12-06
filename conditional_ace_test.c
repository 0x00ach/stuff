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

VOID ParseDACL(PACL Acl) {
	ULONG i = 0, j = 0;
	PVOID xPtr = NULL;
	PACE_HEADER pACE = NULL;
	PACCESS_ALLOWED_ACE pAACE = NULL;
	PACCESS_ALLOWED_OBJECT_ACE pAOACE = NULL;
	PISID pSid = NULL;

	printf("\tDACL raw data:\n"
		"\t\tDacl->AceCount: %d\n"
		"\t\tDacl->AclSize: %d\n"
		"\t\tDacl->AclRevision: %d\n",
		Acl->AceCount,
		Acl->AclSize,
		Acl->AclRevision);
	pACE = (PACE_HEADER)((SIZE_T)Acl + sizeof(ACL));
	for(i = 0; i< Acl->AceCount;i++) {
		printf("\t\tDacl->ACE #%d\n", i);
		printf("\t\t\tHeader.AceSize: %d\n"
			"\t\t\tHeader.AceType: %x\n",
			pACE->AceSize,
			pACE->AceType);

		if (pACE->AceType == ACCESS_ALLOWED_ACE_TYPE)
		printf("\t\t\tHeader.AceType: ACCESS_ALLOWED_ACE_TYPE\n");
		else if (pACE->AceType == ACCESS_DENIED_ACE_TYPE)
		printf("\t\t\tHeader.AceType: ACCESS_DENIED_ACE_TYPE\n");
		else if (pACE->AceType == ACCESS_ALLOWED_COMPOUND_ACE_TYPE)
		printf("\t\t\tHeader.AceType: ACCESS_ALLOWED_COMPOUND_ACE_TYPE\n");
		else if (pACE->AceType == ACCESS_ALLOWED_OBJECT_ACE_TYPE)
		printf("\t\t\tHeader.AceType: ACCESS_ALLOWED_OBJECT_ACE_TYPE\n");
		else if (pACE->AceType == ACCESS_DENIED_OBJECT_ACE_TYPE)
		printf("\t\t\tHeader.AceType: ACCESS_DENIED_OBJECT_ACE_TYPE\n");
		else if (pACE->AceType == ACCESS_ALLOWED_CALLBACK_ACE_TYPE)
		printf("\t\t\tHeader.AceType: ACCESS_ALLOWED_CALLBACK_ACE_TYPE\n");
		else if (pACE->AceType == ACCESS_DENIED_CALLBACK_ACE_TYPE)
		printf("\t\t\tHeader.AceType: ACCESS_DENIED_CALLBACK_ACE_TYPE\n");
		else if (pACE->AceType == ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE)
		printf("\t\t\tHeader.AceType: ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE\n");
		else if (pACE->AceType == ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE)
		printf("\t\t\tHeader.AceType: ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE\n");

		printf("\t\t\tHeader.AceFlags: %d ", pACE->AceFlags);
		if ((pACE->AceFlags & OBJECT_INHERIT_ACE) != 0)
		printf("OBJECT_INHERIT_ACE ");
		if ((pACE->AceFlags & CONTAINER_INHERIT_ACE) != 0)
		printf("CONTAINER_INHERIT_ACE ");
		if ((pACE->AceFlags & NO_PROPAGATE_INHERIT_ACE) != 0)
		printf("NO_PROPAGATE_INHERIT_ACE ");
		if ((pACE->AceFlags & INHERIT_ONLY_ACE) != 0)
		printf("INHERIT_ONLY_ACE ");
		if ((pACE->AceFlags & INHERITED_ACE) != 0)
		printf("INHERITED_ACE ");
		if ((pACE->AceFlags & VALID_INHERIT_FLAGS) != 0)
		printf("VALID_INHERIT_FLAGS ");
		if ((pACE->AceFlags & SUCCESSFUL_ACCESS_ACE_FLAG) != 0)
		printf("SUCCESSFUL_ACCESS_ACE_FLAG ");
		if ((pACE->AceFlags & FAILED_ACCESS_ACE_FLAG) != 0)
		printf("FAILED_ACCESS_ACE_FLAG ");
		printf("\n");

		if (pACE->AceType == ACCESS_ALLOWED_OBJECT_ACE_TYPE ||
			pACE->AceType == ACCESS_DENIED_OBJECT_ACE_TYPE ||
			pACE->AceType == ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE ||
			pACE->AceType == ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE
			) {
			pAOACE = (PACCESS_ALLOWED_OBJECT_ACE)pACE;
			printf("\t\t\tInheritedObjectType: %.8x-%.4x-%.4x-%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x\n"
				"\t\t\tMask: 0x%x\n"
				"\t\t\tObjectType: %.8x-%.4x-%.4x-%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x\n",
				pAOACE->InheritedObjectType.Data1,
				pAOACE->InheritedObjectType.Data2,
				pAOACE->InheritedObjectType.Data3,
				pAOACE->InheritedObjectType.Data4[0],
				pAOACE->InheritedObjectType.Data4[1],
				pAOACE->InheritedObjectType.Data4[2],
				pAOACE->InheritedObjectType.Data4[3],
				pAOACE->InheritedObjectType.Data4[4],
				pAOACE->InheritedObjectType.Data4[5],
				pAOACE->InheritedObjectType.Data4[6],
				pAOACE->InheritedObjectType.Data4[7],
				pAOACE->Mask,
				pAOACE->ObjectType.Data1,
				pAOACE->ObjectType.Data2,
				pAOACE->ObjectType.Data3,
				pAOACE->ObjectType.Data4[0],
				pAOACE->ObjectType.Data4[1],
				pAOACE->ObjectType.Data4[2],
				pAOACE->ObjectType.Data4[3],
				pAOACE->ObjectType.Data4[4],
				pAOACE->ObjectType.Data4[5],
				pAOACE->ObjectType.Data4[6],
				pAOACE->ObjectType.Data4[7]);
			pSid = (PISID)&pAOACE->SidStart;

		}
		else {
			pAACE = (PACCESS_ALLOWED_ACE)pACE;
			printf("\t\t\tMask: 0x%x\n", pAACE->Mask);
			pSid = (PISID)&pAACE->SidStart;
		}

		printf(
			"\t\t\tSID.SubAuthorityCount: %d\n"
			"\t\t\tSID : S-%d-0x%x%x%x%x%x%x",
			pSid->SubAuthorityCount,
			pSid->Revision,
			pSid->IdentifierAuthority.Value[0],
			pSid->IdentifierAuthority.Value[1],
			pSid->IdentifierAuthority.Value[2],
			pSid->IdentifierAuthority.Value[3],
			pSid->IdentifierAuthority.Value[4],
			pSid->IdentifierAuthority.Value[5]);

		xPtr = &pSid->SubAuthority;
		for (j = 0; j < pSid->SubAuthorityCount; j++) {
			printf("-%d", *(PULONG)xPtr);
			xPtr = (PVOID)((SIZE_T)xPtr + sizeof(ULONG));
		}
		printf("\n");

		if ((SIZE_T)xPtr < (SIZE_T)pACE + pACE->AceSize){
			printf("\t\t\tRemaining data:\n\t\t\t\t");
			while ((SIZE_T)xPtr < (SIZE_T)pACE + pACE->AceSize) {
				printf("%.2x", *(PUCHAR)xPtr);
				xPtr = (PVOID)((SIZE_T)xPtr + 1);
			}
			printf("\n");
		}

		pACE = (PACE_HEADER)((SIZE_T)pACE + pACE->AceSize);
	} 
	
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
		"",
		sddl,
		((PISECURITY_DESCRIPTOR_RELATIVE)pSecurityDescriptor)->Revision,
		((PISECURITY_DESCRIPTOR_RELATIVE)pSecurityDescriptor)->Control,
		((PISECURITY_DESCRIPTOR_RELATIVE)pSecurityDescriptor)->Sbz1,
		(SIZE_T)((PISECURITY_DESCRIPTOR_RELATIVE)pSecurityDescriptor)->Dacl + (SIZE_T)pSecurityDescriptor);

	ParseDACL(((PACL)(((PISECURITY_DESCRIPTOR_RELATIVE)pSecurityDescriptor)->Dacl + (SIZE_T)pSecurityDescriptor)));
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
	if (argc > 2) {
		if (!_stricmp(argv[1], "-reg"))
			setToReg(HKEY_LOCAL_MACHINE, argv[2]);

		if (!_stricmp(argv[1], "-file"))
			setToFile(argv[2]);
	}
	else{
		printf("Usage: %s -reg|-file <path>\n"
		"e.g: -file C:\\test.txt\n"
		"e.g: -reg SOFTWARE\\Microsoft (HKLM hive)\n", argv[0]);
	}
	return 0;
}
