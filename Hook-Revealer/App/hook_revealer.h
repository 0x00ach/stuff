#include <windows.h>
#include <stdio.h>
#include <string>
#include <tlhelp32.h>
#include "ntdefines.h"

#define SIOCTL_TYPE 40000
#define IOCTL_DETECT_HOOK\
    CTL_CODE( SIOCTL_TYPE, 0x901, METHOD_BUFFERED, FILE_READ_DATA|FILE_WRITE_DATA)

#define DRIVER_NOT_INSTALLED 0x1
#define DRIVER_STARTED 0x2
#define DRIVER_STOPPED 0x3

typedef struct _module
{
	char* moduleFileName;
	DWORD baseAddr;
	DWORD codeAddr;
	DWORD endOfCodeAddr;
	DWORD eatAddr;
	DWORD endOfEatAddr;
	DWORD iatAddr;
	DWORD iatSize;
	DWORD endOfModule;
	bool isDll;
}module, *pmodule, **ppmodule;

typedef struct _forwardedFunction
{
	pmodule moduleFunc;
	char* functionName;
}forwarded_eat_function, *pforwarded_eat_function, **ppforwarded_eat_function;

class analysis
{
private:
	ppforwarded_eat_function forwardeds;
	int nbforwardeds;

	DWORD currentPid;
	char* currentProcessName;
	HANDLE currentProcessHandle;

	FILE* currentFile;

	char** sys32dllFiles;
	int nbSys32dllFiles;

	ppmodule loadedModules;
	int nbLoadedModules;

	SC_HANDLE manager;
	SC_HANDLE service;

public:
	
	analysis();
	analysis(char* fileName);
	~analysis(){}

	DWORD readDw(DWORD addr);
	WORD readW(DWORD addr);
	BYTE readB(DWORD addr);
	BOOL readMem(DWORD addr, PVOID buffer, ULONG nbBytes);

	void initiateNtEmulations();
	void loadSystem32Dlls();
	bool isSystem32File(char* nom_module);

	void analyseProcesses();
	void process_analysis();

	void analyse_modules();
	void module_analysis(pmodule mod);
	void module_iat_analysis(pmodule mod);
	void analyse_system32(pmodule mod);
	void deleteForwardeds();
	char* whosthisaddr(DWORD addr);

	void pebAnalysisAndLoadModules();
	void deleteModules();

	void analyse_eat(pmodule mod);
	void detect_inline_hook(pmodule mod, char* name, DWORD funcAddr);

	pmodule gmh(char* name);
	bool isForwardedFunction(char* name, pmodule mod);

	int driverStatus();
	bool start_service();
	bool stop_service();
	bool install_driver();
	bool remove_driver();
	bool ssdt();
	void ring0analysis();
	void sCCleanHandles();
};
bool elevate_debug();
bool elevate_driver();
LRESULT CALLBACK callback(HWND fenetrePrincipale, UINT message, WPARAM wParam, LPARAM lParam);

// Emulation de ZwOpenFile
extern NTSTATUS (__stdcall *myNtOpenFile)(
  PHANDLE FileHandle,
  ACCESS_MASK DesiredAccess,
  POBJECT_ATTRIBUTES ObjectAttributes,
  PIO_STATUS_BLOCK IoStatusBlock,
  ULONG ShareAccess,
  ULONG OpenOptions
);
// Emulation de ZwQueryInformationProcess
extern NTSTATUS (__stdcall *myNtQueryInformationProcess)(
  HANDLE ProcessHandle,
  ULONG ProcessInformationClass,
  PVOID ProcessInformation,
  ULONG ProcessInformationLength,
  PULONG ReturnLength
);
// Emulation de ZwOpenProcess
extern NTSTATUS (__stdcall *myNtOpenProcess)(
  PHANDLE ProcessHandle,
  ACCESS_MASK AccessMask,
  POBJECT_ATTRIBUTES ObjectAttributes,
  PCLIENT_ID ClientId 
);
// Emulation de ZwReadFile
extern NTSTATUS (__stdcall *myNtReadFile)(
    HANDLE FileHandle,
    HANDLE Event,
    PIO_APC_ROUTINE ApcRoutine,
    PVOID ApcContext,
	PIO_STATUS_BLOCK IoStatusBlock,
    PVOID Buffer,
    ULONG Length,
    PLARGE_INTEGER ByteOffset,
    PULONG Key
);
// Emulation de ZwOpenFile
extern NTSTATUS (__stdcall *myNtQueryDirectoryFile)(
 HANDLE FileHandle,
 HANDLE Event,
 PIO_APC_ROUTINE ApcRoutine,
 PVOID ApcContext,
 PIO_STATUS_BLOCK IoStatusBlock,
 PVOID FileInformation,
 ULONG Length,
 FILE_INFORMATION_CLASS FileInformationClass,
 BOOLEAN ReturnSingleEntry,
 PUNICODE_STRING FileName,
 BOOLEAN RestartScan
);
extern NTSTATUS (__stdcall *myNtReadVirtualMemory)(
  HANDLE ProcessHandle,
  PVOID BaseAddress,
  PVOID Buffer,
  ULONG NumberOfBytesToRead,
  PULONG NumberOfBytesReaded OPTIONAL
);

//initialisation des nt*
void initiateNtEmulations();
void initRF(PBYTE* funcAddr, DWORD syscallnum); //NtReadFile
void initOF(PBYTE* funcAddr, DWORD syscallnum); //NtOpenFile
void initQDF(PBYTE* funcAddr, DWORD syscallnum); //NtQueryDirectoryFile
void initQIP(PBYTE* funcAddr, DWORD syscallnum); //NtQueryDirectoryFile
void initRVM(PBYTE* funcAddr, DWORD syscallnum); //NtReadVirtualMemory
void initOP(PBYTE* funcAddr, DWORD syscallnum); //NtOpenProcess

/*
wrapper pour simplifier l'utilisation de NtOpenFile / NtReadFile
__in fileName : path absolu du fichier en WSTR, de la forme L"\\??\\C:\\blabla.txt\x00\x00"
__out buffer : tableau de BYTE
__in bufferLen : taille du tableau
__in fileOffset : à partir d'où lire dans le fichier
__out nbBytesRead : nombre d'octets lus
return : DWORD : 0 si erreur
*/
DWORD readFile(PWSTR fileName, PBYTE buffer, int bufferLen, int fileOffset, int* nbBytesRead);
/*
wrapper pour simplifier le listing de répertoires
__in fileName : nom du répertoire
__in match : pattern à respecter (*.dll par exemple)
return : char ** : pointeur sur un tableau de char* (le dernier membre vaut NULL)
*/
char** listDir(PWSTR fileName, PWSTR match);