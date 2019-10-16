#include <windows.h>
#include <stdio.h>
#include <userenv.h>

void trypasswordonaccountA(char* password, char* uname, char* domainname) {

	STARTUPINFOA si = { 0 };
	PROCESS_INFORMATION pi = { 0 };
	si.cb = sizeof(STARTUPINFOW);

	if (CreateProcessWithLogonA(uname,
		domainname,
		password,
		0,
		"cmd",
		"/c whoami",
		CREATE_NEW_CONSOLE,
		NULL,
		NULL,
		&si,
		&pi
		) == TRUE){
		printf("OK\n");
	}
	else if (GetLastError() != 0x52e){
		printf("FAIL\n");
	}

}

int main(int argc, char** argv) {

    if(argc < 4) {
        printf("Usage: %s password username domain\n", argv[0]);
        return 1;
    }
    trypasswordonaccountA(argv[1],argv[2],argv[3]);
    return 0;
}
