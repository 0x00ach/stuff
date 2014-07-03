//WIN32 defines
typedef LONG NTSTATUS;
#define STATUS_NO_MORE_FILES 0x80000006


typedef struct {   
    ULONG NextEntryOffset;   
    ULONG FileIndex;   
    LARGE_INTEGER CreationTime;   
    LARGE_INTEGER LastAccessTime;   
    LARGE_INTEGER LastWriteTime;   
    LARGE_INTEGER ChangeTime;   
    LARGE_INTEGER EndOfFile;   
    LARGE_INTEGER AllocationSize;   
    ULONG FileAttributes;   
    ULONG FileNameLength;   
    union {   
        struct {   
            WCHAR FileName[1];   
        } FileDirectoryInformationClass;   

        struct {   
            DWORD dwUknown1;   
            WCHAR FileName[1];   
        } FileFullDirectoryInformationClass;   

        struct {   
            DWORD dwUknown2;   
            USHORT AltFileNameLen;   
            WCHAR AltFileName[12];   
            WCHAR FileName[1];   
    } FileBothDirectoryInformationClass;   
    };   
} FILE_QUERY_DIRECTORY, *PFILE_QUERY_DIRECTORY; 
typedef struct _UNICODE_STRING
{
	USHORT Length;
	USHORT MaximumLength;
	PWSTR Buffer;
}UNICODE_STRING, * PUNICODE_STRING;
typedef struct _CLIENT_ID
{
	HANDLE UniqueProcess;
	HANDLE UniqueThread;
}CLIENT_ID, *PCLIENT_ID;
typedef struct _VM_COUNTERS{
	DWORD PeakVirtualSize;
	DWORD VirtualSize;
	DWORD PageFaultCount;
	DWORD PeakWorkingSetSize;
	DWORD WorkingSetSize;
	DWORD QuotaPeakPagedPoolUsage;
	DWORD QuotaPagedPoolUsage;
	DWORD QuotaPeakNonPagedPoolUsage;
	DWORD QuotaNonPagedPoolUsage;
	DWORD PageFileUsage;
	DWORD PeakPagefileUsage;	
}VM_COUNTERS, *PVM_COUNTERS;
typedef struct _LDR_MODULE {

  LIST_ENTRY              InLoadOrderModuleList;
  //+0 : .flink
  //+4 : .blink
  LIST_ENTRY              InMemoryOrderModuleList; //+8
  //+8 : .flink
  //+12 : .blink
  LIST_ENTRY              InInitializationOrderModuleList; //+16
  //+16 : .flink
  //+20 : .blink
  PVOID                   BaseAddress; //+24
  PVOID                   EntryPoint; //+28
  ULONG                   SizeOfImage; //+32
  UNICODE_STRING          FullDllName; //+36
  //len +36
  //max +38
  //buffer +40
  UNICODE_STRING          BaseDllName; //+44
  //len +44
  //max +46
  //buffer +48
  ULONG                   Flags;
  SHORT                   LoadCount;
  SHORT                   TlsIndex;
  LIST_ENTRY              HashTableEntry;
  ULONG                   TimeDateStamp;


} LDR_MODULE, *PLDR_MODULE;
typedef enum _FILE_INFORMATION_CLASS {


    FileDirectoryInformation=1,
    FileFullDirectoryInformation,
    FileBothDirectoryInformation,
    FileBasicInformation,
    FileStandardInformation,
    FileInternalInformation,
    FileEaInformation,
    FileAccessInformation,
    FileNameInformation,
    FileRenameInformation,
    FileLinkInformation,
    FileNamesInformation,
    FileDispositionInformation,
    FilePositionInformation,
    FileFullEaInformation,
    FileModeInformation,
    FileAlignmentInformation,
    FileAllInformation,
    FileAllocationInformation,
    FileEndOfFileInformation,
    FileAlternateNameInformation,
    FileStreamInformation,
    FilePipeInformation,
    FilePipeLocalInformation,
    FilePipeRemoteInformation,
    FileMailslotQueryInformation,
    FileMailslotSetInformation,
    FileCompressionInformation,
    FileCopyOnWriteInformation,
    FileCompletionInformation,
    FileMoveClusterInformation,
    FileQuotaInformation,
    FileReparsePointInformation,
    FileNetworkOpenInformation,
    FileObjectIdInformation,
    FileTrackingInformation,
    FileOleDirectoryInformation,
    FileContentIndexInformation,
    FileInheritContentIndexInformation,
    FileOleInformation,
    FileMaximumInformation



} FILE_INFORMATION_CLASS, *PFILE_INFORMATION_CLASS;
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#define FILE_NON_DIRECTORY_FILE 0x00000040L
#define FILE_DIRECTORY_FILE 0x00000001
#define OBJ_INHERIT 0x00000002L
#define OBJ_CASE_INSENSITIVE 0x00000040L
#define SysInfoClassProcess 5
typedef struct _SYSTEM_THREAD_INFORMATION{
	LARGE_INTEGER KernelTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER CreateTime;
	ULONG WaitTime;
	PVOID StartAddress;
	CLIENT_ID ClientId;
	LONG Priority;
	LONG BasePriority;
	ULONG ContextSwitchCount;
	LONG State;
	LONG WaitReason;
}SYSTEM_THREAD_INFORMATION, *PSYSTEM_THREAD_INFORMATION;
typedef struct _SYSTEM_PROCESS_INFORMATION{
	DWORD NextEntryOfData;
	ULONG ThreadCount;
	ULONG Reserved1[6];
	LARGE_INTEGER CreateTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER KernelTime;
	UNICODE_STRING ProcessName;
	LONG BasePriority;
	ULONG ProcessId;
	ULONG InheritedFromProcessId;
	ULONG HandleCount;
	ULONG Reserved2[2];
	VM_COUNTERS VmCounters;
	IO_COUNTERS IoCounters;
	SYSTEM_THREAD_INFORMATION Threads[1];
} SYSTEM_PROCESS_INFORMATION, *PSYSTEM_PROCESS_INFORMATION;
typedef struct _IO_STATUS_BLOCK{
	union{
		LONG Status;
		PVOID Pointer;
	};
	ULONG Information;
}IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;
typedef VOID (NTAPI *PIO_APC_ROUTINE)
(
	PVOID ApcContext,
	PIO_STATUS_BLOCK IoStatusBlock,
	ULONG Reserved
);
typedef struct _FILE_NAMES_INFORMATION{
	ULONG NextEntryOffset;
	ULONG Unknown;
	ULONG FileNameLength;
	WCHAR FileName[1];
}FILE_NAMES_INFORMATION, *PFILE_NAMES_INFORMATION;
typedef struct _FILE_DIRECTORY_INFORMATION{
	ULONG NextEntryOffset;
	ULONG Unknown;
	LARGE_INTEGER CreationTime;
	LARGE_INTEGER LastAccessTime;
	LARGE_INTEGER LastWriteTime;
	LARGE_INTEGER ChangeTime;
	LARGE_INTEGER EndOfFile;
	LARGE_INTEGER AllocationSize;
	ULONG FileAttributes;
	ULONG FileNameLength;
	WCHAR FileName[1];
}FILE_DIRECTORY_INFORMATION, *PFILE_DIRECTORY_INFORMATION;
typedef struct _FILE_FULL_DIRECTORY_INFORMATION{
	ULONG NextEntryOffset;
	ULONG Unknown;
	LARGE_INTEGER CreationTime;
	LARGE_INTEGER LastAccessTime;
	LARGE_INTEGER LastWriteTime;
	LARGE_INTEGER ChangeTime;
	LARGE_INTEGER EndOfFile;
	LARGE_INTEGER AllocationSize;
	ULONG FileAttributes;
	ULONG FileNameLength;
	ULONG EaInformationLength;
	WCHAR FileName[1];
}FILE_FULL_DIRECTORY_INFORMATION, *PFILE_FULL_DIRECTORY_INFORMATION;
typedef struct _FILE_BOTH_DIRECTORY_INFORMATION{
	ULONG NextEntryOffset;
	ULONG Unknown;
	LARGE_INTEGER CreationTime;
	LARGE_INTEGER LastAccessTime;
	LARGE_INTEGER LastWriteTime;
	LARGE_INTEGER ChangeTime;
	LARGE_INTEGER EndOfFile;
	LARGE_INTEGER AllocationSize;
	ULONG FileAttributes;
	ULONG FileNameLength;
	ULONG EaInformationLength;
	WCHAR AlternateNameLength;
	WCHAR AlternateName[12];
	WCHAR FileName[1];
}FILE_BOTH_DIRECTORY_INFORMATION, *PFILE_BOTH_DIRECTORY_INFORMATION;
typedef struct _FILE_ID_FULL_DIRECTORY_INFORMATION {
    ULONG NextEntryOffset;
    ULONG FileIndex;
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    LARGE_INTEGER EndOfFile;
    LARGE_INTEGER AllocationSize;
    ULONG FileAttributes;
    ULONG FileNameLength;
    ULONG EaSize;
    LARGE_INTEGER FileId;
    WCHAR FileName[1];
} FILE_ID_FULL_DIRECTORY_INFORMATION, *PFILE_ID_FULL_DIRECTORY_INFORMATION;
typedef struct _FILE_ID_BOTH_DIRECTORY_INFORMATION {
    ULONG NextEntryOffset;
    ULONG FileIndex;
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    LARGE_INTEGER EndOfFile;
    LARGE_INTEGER AllocationSize;
    ULONG FileAttributes;
    ULONG FileNameLength;
    ULONG EaSize;
    CCHAR ShortNameLength;
    WCHAR ShortName[12];
    LARGE_INTEGER FileId;
    WCHAR FileName[1];
} FILE_ID_BOTH_DIRECTORY_INFORMATION, *PFILE_ID_BOTH_DIRECTORY_INFORMATION;
typedef struct _PEB_LDR_DATA
{
	ULONG Length;//+0
	BOOLEAN Initialized; //+4
	PVOID SsHandle; //+5
	LIST_ENTRY InLoadOrderModuleList; 
	LIST_ENTRY InMemoryOrderModuleList; 
	LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;
typedef struct _RTL_DRIVE_LETTER_CURDIR {
  USHORT                  Flags;
  USHORT                  Length;
  ULONG                   TimeStamp;
  UNICODE_STRING          DosPath;
} RTL_DRIVE_LETTER_CURDIR, *PRTL_DRIVE_LETTER_CURDIR;
typedef struct _RTL_USER_PROCESS_PARAMETERS {
  ULONG                   MaximumLength; //+0
  ULONG                   Length; //+4
  ULONG                   Flags; //+8
  ULONG                   DebugFlags; //+12
  PVOID                   ConsoleHandle; //16
  ULONG                   ConsoleFlags; //+20
  HANDLE                  StdInputHandle; //+24
  HANDLE                  StdOutputHandle; //+28
  HANDLE                  StdErrorHandle; //+32
  UNICODE_STRING          CurrentDirectoryPath; //+36 : len
  //+36 : len
  //+38 : max
  //+40 : buffer
  HANDLE                  CurrentDirectoryHandle; //+44
  UNICODE_STRING          DllPath; //+48
  //+48 : len
  //+50 : max
  //+52 : buffer
  UNICODE_STRING          ImagePathName; //+56
  //+56 : len
  //+58 : max
  //+60 : buffer
  UNICODE_STRING          CommandLine; //+64
  //+64 : len
  //+66 : max
  //+68 : buffer
  PVOID                   Environment;
  ULONG                   StartingPositionLeft;
  ULONG                   StartingPositionTop;
  ULONG                   Width;
  ULONG                   Height;
  ULONG                   CharWidth;
  ULONG                   CharHeight;
  ULONG                   ConsoleTextAttributes;
  ULONG                   WindowFlags;
  ULONG                   ShowWindowFlags;
  UNICODE_STRING          WindowTitle;
  UNICODE_STRING          DesktopName;
  UNICODE_STRING          ShellInfo;
  UNICODE_STRING          RuntimeData;
  RTL_DRIVE_LETTER_CURDIR DLCurrentDirectory[0x20];
} RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;

typedef void (*PPEBLOCKROUTINE)(
PVOID PebLock
);
 typedef void** PPVOID;
 
typedef struct _PEB_FREE_BLOCK
{
     PVOID Next;
     ULONG Size;
} PEB_FREE_BLOCK, *PPEB_FREE_BLOCK;
typedef struct _PEB {
  BOOLEAN                 InheritedAddressSpace;  //+0
  BOOLEAN                 ReadImageFileExecOptions;  //+1
  BOOLEAN                 BeingDebugged; //+2
  BOOLEAN                 Spare;  //+3
  HANDLE                  Mutant;  //+4
  PVOID                   ImageBaseAddress; //+8
  PPEB_LDR_DATA           LoaderData; //+12
  PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
  PVOID                   SubSystemData;
  PVOID                   ProcessHeap;
  PVOID                   FastPebLock;
  PPEBLOCKROUTINE         FastPebLockRoutine;
  PPEBLOCKROUTINE         FastPebUnlockRoutine;
  ULONG                   EnvironmentUpdateCount;
  PPVOID                  KernelCallbackTable;
  PVOID                   EventLogSection;
  PVOID                   EventLog;
  PPEB_FREE_BLOCK         FreeList;
  ULONG                   TlsExpansionCounter;
  PVOID                   TlsBitmap;
  ULONG                   TlsBitmapBits[0x2];
  PVOID                   ReadOnlySharedMemoryBase;
  PVOID                   ReadOnlySharedMemoryHeap;
  PPVOID                  ReadOnlyStaticServerData;
  PVOID                   AnsiCodePageData;
  PVOID                   OemCodePageData;
  PVOID                   UnicodeCaseTableData;
  ULONG                   NumberOfProcessors;
  ULONG                   NtGlobalFlag;
  BYTE                    Spare2[0x4];
  LARGE_INTEGER           CriticalSectionTimeout;
  ULONG                   HeapSegmentReserve;
  ULONG                   HeapSegmentCommit;
  ULONG                   HeapDeCommitTotalFreeThreshold;
  ULONG                   HeapDeCommitFreeBlockThreshold;
  ULONG                   NumberOfHeaps;
  ULONG                   MaximumNumberOfHeaps;
  PPVOID                  *ProcessHeaps;
  PVOID                   GdiSharedHandleTable;
  PVOID                   ProcessStarterHelper;
  PVOID                   GdiDCAttributeList;
  PVOID                   LoaderLock;
  ULONG                   OSMajorVersion;
  ULONG                   OSMinorVersion;
  ULONG                   OSBuildNumber;
  ULONG                   OSPlatformId;
  ULONG                   ImageSubSystem;
  ULONG                   ImageSubSystemMajorVersion;
  ULONG                   ImageSubSystemMinorVersion;
  ULONG                   GdiHandleBuffer[0x22];
  ULONG                   PostProcessInitRoutine;
  ULONG                   TlsExpansionBitmap;
  BYTE                    TlsExpansionBitmapBits[0x80];
  ULONG                   SessionId;
} PEB, *PPEB;
typedef struct _OBJECT_ATTRIBUTES
{
	ULONG Length;
	HANDLE RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG Attributes;
	PVOID SecurityDescriptor;
	PVOID SecurityQualityOfService;
}OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;
typedef struct _PROCESS_BASIC_INFORMATION {
    PVOID Reserved1;
    PPEB PebBaseAddress;
    PVOID Reserved2[2];
    ULONG_PTR UniqueProcessId;
    PVOID Reserved3;
} PROCESS_BASIC_INFORMATION;