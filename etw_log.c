#define INITGUID 
#include <windows.h>
#include <stdio.h>
#include <conio.h>
#include <strsafe.h>
#include <wmistr.h>
#include <evntrace.h>
#include <Objbase.h>
#include <evntcons.h>

#define PROCESS_TRACE_MODE_REAL_TIME 0x00000100
#define PROCESS_TRACE_MODE_RAW_TIMESTAMP 0x00001000
#define PROCESS_TRACE_MODE_EVENT_RECORD 0x10000000

static const GUID myGuid = { 0xdeadbeef, 0x1337, 0x1337, { 0xAA, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11 } };

/***************************************************************************
***************************************************************************
***************************************************************************

HELPERS

***************************************************************************
***************************************************************************
***************************************************************************/

static DWORD WINAPI Win32TracingThread(LPVOID Parameter)
{
	ULONG status = ProcessTrace((PTRACEHANDLE)Parameter, 1, 0, 0);
	if (status != ERROR_SUCCESS)
		printf("ProcessTrace failed with %d\n", status);
	return(0);
}

void DumpHex(const void* data, size_t size) {
	char ascii[17];
	size_t i, j;
	ascii[16] = '\0';
	for (i = 0; i < size; ++i) {
		printf("%02X ", ((unsigned char*)data)[i]);
		if (((unsigned char*)data)[i] >= ' ' && ((unsigned char*)data)[i] <= '~') {
			ascii[i % 16] = ((unsigned char*)data)[i];
		}
		else {
			ascii[i % 16] = '.';
		}
		if ((i + 1) % 8 == 0 || i + 1 == size) {
			printf(" ");
			if ((i + 1) % 16 == 0) {
				printf("|  %s \n", ascii);
			}
			else if (i + 1 == size) {
				ascii[(i + 1) % 16] = '\0';
				if ((i + 1) % 16 <= 8) {
					printf(" ");
				}
				for (j = (i + 1) % 16; j < 16; ++j) {
					printf("   ");
				}
				printf("|  %s \n", ascii);
			}
		}
	}
}


/***************************************************************************
 ***************************************************************************
 ***************************************************************************

 IPC TRACER

 ***************************************************************************
 ***************************************************************************
***************************************************************************/

struct __declspec(uuid("{2957313D-FCAA-5D4A-2F69-32CE5F0AC44E}")) DBG_COM_RUNDOWNINSTRUMENTATION;
static const auto DBG_COM_RUNDOWNINSTRUMENTATION_GUID = __uuidof(DBG_COM_RUNDOWNINSTRUMENTATION);
struct __declspec(uuid("{6AD52B32-D609-4BE9-AE07-CE8DAE937E39}")) DBG_RPC;
static const auto DBG_RPC_GUID = __uuidof(DBG_RPC); 
struct __declspec(uuid("{F4AED7C7-A898-4627-B053-44A7CAA12FCD}")) DBG_RPC_EVENTS;
static const auto DBG_RPC_EVENTS_GUID = __uuidof(DBG_RPC_EVENTS);
struct __declspec(uuid("{edd08927-9cc4-4e65-b970-c2560fb5c289}")) KERNEL_FILE;
static const auto KERNEL_FILE_GUID = __uuidof(KERNEL_FILE);
struct __declspec(uuid("{988c59c5-0a1c-45b6-a555-0c62276e327d}")) SMB_CLIENT;
static const auto SMB_CLIENT_GUID = __uuidof(SMB_CLIENT);

DEFINE_GUID( /* 45d8cccd-539f-4b72-a8b7-5c683142609a */
	ALPC_GUID,
	0x45d8cccd,
	0x539f,
	0x4b72,
	0xa8, 0xb7, 0x5c, 0x68, 0x31, 0x42, 0x60, 0x9a
	);
DEFINE_GUID( /* 3d6fa8d4-fe05-11d0-9dda-00c04fd7ba7c */
	DiskIoGuid,
	0x3d6fa8d4,
	0xfe05,
	0x11d0,
	0x9d, 0xda, 0x00, 0xc0, 0x4f, 0xd7, 0xba, 0x7c
	);
static const  GUID RundownGuid = { 0x68fdd900, 0x4a3e, 0x11d1, { 0x84, 0xf4, 0x00, 0x00, 0xf8, 0x04, 0x64, 0xe3 } };

static void WINAPI IPCEventRecordCallback(EVENT_RECORD *EventRecord)
{
	EVENT_HEADER &Header = EventRecord->EventHeader;
	ULONG c = 0;
	PEVENT_HEADER_EXTENDED_DATA_ITEM ptr = NULL;
	GUID* guidPtr, *guidPtr2;


	if (Header.ProviderId.Data1 == EventTraceConfigGuid.Data1 &&
		Header.ProviderId.Data2 == EventTraceConfigGuid.Data2 &&
		Header.ProviderId.Data3 == EventTraceConfigGuid.Data3)
		return;
	if (Header.ProviderId.Data1 == RundownGuid.Data1 &&
		Header.ProviderId.Data2 == RundownGuid.Data2 &&
		Header.ProviderId.Data3 == RundownGuid.Data3)
		return;
	if (Header.ProviderId.Data1 == DiskIoGuid.Data1 &&
		Header.ProviderId.Data2 == DiskIoGuid.Data2 &&
		Header.ProviderId.Data3 == DiskIoGuid.Data3)
		return;


	// ==================== SMB =====================
	
	if (Header.ProviderId.Data1 == SMB_CLIENT_GUID.Data1 &&
		Header.ProviderId.Data2 == SMB_CLIENT_GUID.Data2 &&
		Header.ProviderId.Data3 == SMB_CLIENT_GUID.Data3) {

		if (Header.EventDescriptor.Id == 40000) {

			if (*(PUSHORT)((SIZE_T)EventRecord->UserData + 0x34) == 0x5) {

				printf("SMB %d - SMB2Create - PID %d - IPv4 address %d.%d.%d.%d:%d - resource %.*S\n",
					Header.EventDescriptor.Id,
					Header.ProcessId,
					*(PUCHAR)((SIZE_T)EventRecord->UserData + 0xc),
					*(PUCHAR)((SIZE_T)EventRecord->UserData + 0xd),
					*(PUCHAR)((SIZE_T)EventRecord->UserData + 0xe),
					*(PUCHAR)((SIZE_T)EventRecord->UserData + 0xf),
					(*(PUCHAR)((SIZE_T)EventRecord->UserData + 0xa) << 8) | *(PUCHAR)((SIZE_T)EventRecord->UserData + 0xb),
					*(PUSHORT)((SIZE_T)EventRecord->UserData + 0x94),
					(PWSTR)((SIZE_T)EventRecord->UserData + 0xa0));
			}
		}

		return;
	}
		


	// ==================== FILE =====================

	if (Header.ProviderId.Data1 == KERNEL_FILE_GUID.Data1 &&
		Header.ProviderId.Data2 == KERNEL_FILE_GUID.Data2 &&
		Header.ProviderId.Data3 == KERNEL_FILE_GUID.Data3) {

		if (Header.EventDescriptor.Id == 12 || Header.EventDescriptor.Id == 30) {

			// on skippe tout ce qui est sur le disque
			if (*(PULONGLONG)((SIZE_T)EventRecord->UserData + 0x20) == 0x007600650044005c &&
				*(PULONGLONG)((SIZE_T)EventRecord->UserData + 0x30) == 0x0064007200610048)
				return;

			printf("FILE %d - PID %d - FileName %S - CreateOptions %.8X - CreateAttributes %.8X - ShareAccess %.8X\n",
				Header.EventDescriptor.Id,
				Header.ProcessId,
				(PWSTR)((SIZE_T)EventRecord->UserData + 0x20),
				*(PULONG)((SIZE_T)(EventRecord->UserData) + 0x14),
				*(PULONG)((SIZE_T)(EventRecord->UserData) + 0x18),
				*(PULONG)((SIZE_T)(EventRecord->UserData) + 0x1C));
		}
		else if (Header.EventDescriptor.Id == 10 || Header.EventDescriptor.Id == 11) {

			// on skippe tout ce qui est sur le disque
			if (*(PULONGLONG)((SIZE_T)EventRecord->UserData + 0x8) == 0x007600650044005c &&
				*(PULONGLONG)((SIZE_T)EventRecord->UserData + 0x18) == 0x0064007200610048)
				return;

			printf("FILE %d - PID %d - FileName %S\n",
				Header.EventDescriptor.Id,
				Header.ProcessId,
				(PWSTR)((SIZE_T)EventRecord->UserData + 0x8));

		}


	}

	return;

	// ==================== DCOM =====================

	if (Header.ProviderId.Data1 == DBG_COM_RUNDOWNINSTRUMENTATION_GUID.Data1 &&
		Header.ProviderId.Data2 == DBG_COM_RUNDOWNINSTRUMENTATION_GUID.Data2 &&
		Header.ProviderId.Data3 == DBG_COM_RUNDOWNINSTRUMENTATION_GUID.Data3) {

		if (Header.EventDescriptor.Id == 22 ||
			Header.EventDescriptor.Id == 23 ||
			Header.EventDescriptor.Id == 21 ||
			Header.EventDescriptor.Id == 24 ||
			Header.EventDescriptor.Id == 12 ||
			Header.EventDescriptor.Id == 3 ||
			Header.EventDescriptor.Id == 15 ||
			Header.EventDescriptor.Id == 4) {
			printf("COM %d - PID %d - OID %I64X\n",
				Header.EventDescriptor.Id,
				Header.ProcessId,
				*(PULONGLONG)EventRecord->UserData);

			return;
		}

		if (Header.EventDescriptor.Id == 11 ||
			Header.EventDescriptor.Id == 25) {

			printf("COM %d - PID %d - OID %I64X - ClientProcessId %d\n",
				Header.EventDescriptor.Id,
				Header.ProcessId,
				*(PULONGLONG)EventRecord->UserData,
				*(PULONG)((SIZE_T)(EventRecord->UserData)+8));

			return;
		}


		if (Header.EventDescriptor.Id == 1 || 
			Header.EventDescriptor.Id == 2) {

			guidPtr = (GUID*)((SIZE_T)EventRecord->UserData + 8);
			guidPtr2 = (GUID*)((SIZE_T)EventRecord->UserData + 0x18);
			printf("COM %d - PID %d - OID %I64X - IID {%.8x-%.4x-%.4x-%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x} - IPID {%.8x-%.4x-%.4x-%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x}\n",
				Header.EventDescriptor.Id,
				Header.ProcessId,
				*(PULONGLONG)EventRecord->UserData,
				guidPtr->Data1,
				guidPtr->Data2,
				guidPtr->Data3,
				guidPtr->Data4[0],
				guidPtr->Data4[1],
				guidPtr->Data4[2],
				guidPtr->Data4[3],
				guidPtr->Data4[4],
				guidPtr->Data4[5],
				guidPtr->Data4[6],
				guidPtr->Data4[7],
				guidPtr2->Data1,
				guidPtr2->Data2,
				guidPtr2->Data3,
				guidPtr2->Data4[0],
				guidPtr2->Data4[1],
				guidPtr2->Data4[2],
				guidPtr2->Data4[3],
				guidPtr2->Data4[4],
				guidPtr2->Data4[5],
				guidPtr2->Data4[6],
				guidPtr2->Data4[7]);
			return;
		}

	}


	// ==================== RPC =====================

	if (Header.ProviderId.Data1 == DBG_RPC_GUID.Data1 &&
		Header.ProviderId.Data2 == DBG_RPC_GUID.Data2 &&
		Header.ProviderId.Data3 == DBG_RPC_GUID.Data3) {

		if (Header.EventDescriptor.Opcode == 0 ||
			Header.EventDescriptor.Opcode == 2)
			return;
		else if (Header.EventDescriptor.Opcode == 1) {
			PWSTR NetworkAddrPtr = (PWSTR)((SIZE_T)EventRecord->UserData + 0x18);
			PWSTR EndpointPtr = (PWSTR)((SIZE_T)EventRecord->UserData + 0x18 + sizeof(WCHAR)*(wcslen(NetworkAddrPtr)+1));
			char* mode = "client";
			if (Header.EventDescriptor.Task == 2)
				mode = "serveur";

			guidPtr = (GUID*)((SIZE_T)EventRecord->UserData);
			printf("RPC 1 - %s - PID %d - UUID {%.8x-%.4x-%.4x-%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x} - Protocol %x - Network Addr %S - Endpoint %S - Procedure 0x%x\n",
				mode,
				Header.ProcessId,
				guidPtr->Data1,
				guidPtr->Data2,
				guidPtr->Data3,
				guidPtr->Data4[0],
				guidPtr->Data4[1],
				guidPtr->Data4[2],
				guidPtr->Data4[3],
				guidPtr->Data4[4],
				guidPtr->Data4[5],
				guidPtr->Data4[6],
				guidPtr->Data4[7],
				*(PULONG)((SIZE_T)EventRecord->UserData + 0x14),
				NetworkAddrPtr,
				EndpointPtr,
				*(PULONG)((SIZE_T)EventRecord->UserData + 0x10));
			return;
		}

	}


	// ==================== ALPC =====================
	if (Header.ProviderId.Data1 == ALPC_GUID.Data1 &&
		Header.ProviderId.Data2 == ALPC_GUID.Data2 &&
		Header.ProviderId.Data3 == ALPC_GUID.Data3) {

		if (Header.EventDescriptor.Opcode == 36) {
			printf("ALPC 36 - PID %d - %.*S\n", Header.ProcessId, EventRecord->UserDataLength, (PWSTR)((SIZE_T)EventRecord->UserData + sizeof(ULONG)));
			return;
		}
		else if (
			Header.EventDescriptor.Opcode == 5 || 
			Header.EventDescriptor.Opcode == 33 ||
			Header.EventDescriptor.Opcode == 34 ||
			Header.EventDescriptor.Opcode == 35 ||
			Header.EventDescriptor.Opcode == 37 ||
			Header.EventDescriptor.Opcode == 38 ||
			Header.EventDescriptor.Opcode == 39 ||
			Header.EventDescriptor.Opcode == 41) {
			return;
		}
	}

	// Process event here.
	printf("Event received!\n");
	printf("\tProcessID: %d\n", Header.ProcessId);
	printf("\tThreadId: %d\n", Header.ThreadId);
	printf("\tProviderID: {%.8x-%.4x-%.4x-%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x}\n",
		Header.ProviderId.Data1,
		Header.ProviderId.Data2,
		Header.ProviderId.Data3,
		Header.ProviderId.Data4[0],
		Header.ProviderId.Data4[1],
		Header.ProviderId.Data4[2],
		Header.ProviderId.Data4[3],
		Header.ProviderId.Data4[4],
		Header.ProviderId.Data4[5],
		Header.ProviderId.Data4[6],
		Header.ProviderId.Data4[7]);
	printf("\tActivityID: {%.8x-%.4x-%.4x-%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x}\n",
		Header.ActivityId.Data1,
		Header.ActivityId.Data2,
		Header.ActivityId.Data3,
		Header.ActivityId.Data4[0],
		Header.ActivityId.Data4[1],
		Header.ActivityId.Data4[2],
		Header.ActivityId.Data4[3],
		Header.ActivityId.Data4[4],
		Header.ActivityId.Data4[5],
		Header.ActivityId.Data4[6],
		Header.ActivityId.Data4[7]);
	if (Header.EventProperty == EVENT_HEADER_PROPERTY_XML)
		printf("\tEventProperty: EVENT_HEADER_PROPERTY_XML\n");
	if (Header.EventProperty == EVENT_HEADER_PROPERTY_FORWARDED_XML)
		printf("\tEventProperty: EVENT_HEADER_PROPERTY_FORWARDED_XML\n");
	if (Header.EventProperty == EVENT_HEADER_PROPERTY_LEGACY_EVENTLOG)
		printf("\tEventProperty: EVENT_HEADER_PROPERTY_LEGACY_EVENTLOG\n");
	printf("\tTimestamp: %x\n", Header.TimeStamp.QuadPart);
	printf("\tDescriptor.ID: %d\n", Header.EventDescriptor.Id);
	printf("\tDescriptor.Version: %d\n", Header.EventDescriptor.Version);
	printf("\tDescriptor.Channel: %d\n", Header.EventDescriptor.Channel);
	printf("\tDescriptor.Level: %d\n", Header.EventDescriptor.Level);
	printf("\tDescriptor.Version: %d\n", Header.EventDescriptor.Version);
	printf("\tDescriptor.Opcode: %d\n", Header.EventDescriptor.Opcode);
	printf("\tDescriptor.Task: %d\n", Header.EventDescriptor.Task);
	printf("\tExtendedDataCount: %x\n", EventRecord->ExtendedDataCount);
	if (EventRecord->ExtendedDataCount != 0) {
		ptr = EventRecord->ExtendedData;
		printf("\tExtendedData\n");
		for (c = 0; c < EventRecord->ExtendedDataCount; c++) {
			if (ptr[c].ExtType == EVENT_HEADER_EXT_TYPE_RELATED_ACTIVITYID)
				printf("\t\tEVENT_HEADER_EXT_TYPE_RELATED_ACTIVITYID\n");
			else if (ptr[c].ExtType == EVENT_HEADER_EXT_TYPE_SID)
				printf("\t\tEVENT_HEADER_EXT_TYPE_SID\n");
			else if (ptr[c].ExtType == EVENT_HEADER_EXT_TYPE_TS_ID)
				printf("\t\tEVENT_HEADER_EXT_TYPE_TS_ID\n");
			else if (ptr[c].ExtType == EVENT_HEADER_EXT_TYPE_INSTANCE_INFO)
				printf("\t\tEVENT_HEADER_EXT_TYPE_INSTANCE_INFO\n");
			else if (ptr[c].ExtType == EVENT_HEADER_EXT_TYPE_STACK_TRACE32)
				printf("\t\tEVENT_HEADER_EXT_TYPE_STACK_TRACE32\n");
			else if (ptr[c].ExtType == EVENT_HEADER_EXT_TYPE_STACK_TRACE64)
				printf("\t\tEVENT_HEADER_EXT_TYPE_STACK_TRACE64\n");
			else if (ptr[c].ExtType == EVENT_HEADER_EXT_TYPE_EVENT_SCHEMA_TL)
				printf("\t\tEVENT_HEADER_EXT_TYPE_EVENT_SCHEMA_TL\n");
			else if (ptr[c].ExtType == EVENT_HEADER_EXT_TYPE_PROV_TRAITS)
				printf("\t\tEVENT_HEADER_EXT_TYPE_PROV_TRAITS\n");
			else if (ptr[c].ExtType == EVENT_HEADER_EXT_TYPE_PEBS_INDEX)
				printf("\t\tEVENT_HEADER_EXT_TYPE_PEBS_INDEX\n");
			else if (ptr[c].ExtType == EVENT_HEADER_EXT_TYPE_PSM_KEY)
				printf("\t\tEVENT_HEADER_EXT_TYPE_PSM_KEY\n");
			else if (ptr[c].ExtType == EVENT_HEADER_EXT_TYPE_PMC_COUNTERS)
				printf("\t\tEVENT_HEADER_EXT_TYPE_PMC_COUNTERS\n");
			else if (ptr[c].ExtType == EVENT_HEADER_EXT_TYPE_PROCESS_START_KEY)
				printf("\t\tEVENT_HEADER_EXT_TYPE_PROCESS_START_KEY\n");
			else
				printf("\t\tUNDEFINED: %x\n", ptr[c].ExtType);
		}
	}
	printf("\tUser data length: %x\n", EventRecord->UserDataLength);
	DumpHex(EventRecord->UserData, EventRecord->UserDataLength);
	printf("\n");

}



void IPCTracer(ULONG secondsToWait) {

	ULONG status = ERROR_SUCCESS;
	TRACEHANDLE SessionHandle = 0, SystemSessionHandle = 0;
	TRACEHANDLE SystemConsumerHandle = 0, ConsumerHandle = 0;
	EVENT_TRACE_PROPERTIES* pSessionProperties = NULL, *pSystemSessionProperties=NULL;
	EVENT_TRACE_LOGFILEA traceLogfile = { 0 };
	ULONG BufferSize = 0;
	char titi[200];
	DWORD ThreadID = 0;
	HANDLE ThreadHandle = NULL;
	char* outFileNameSystem = "IPCTracerSys.etl";
	char* outFileName = "IPCTracerStd.etl";
	ULONG enableFlags = EVENT_TRACE_FLAG_ALPC;
	ULONG size = 5;



	///////////////////// Activation du systemTraceControl dans un 1er temps

	BufferSize = sizeof(EVENT_TRACE_PROPERTIES) + strlen(outFileNameSystem) + 1 + strlen(KERNEL_LOGGER_NAMEA) + 1;
	pSystemSessionProperties = (EVENT_TRACE_PROPERTIES*)malloc(BufferSize);
	if (NULL == pSystemSessionProperties)
	{
		wprintf(L"Unable to allocate %d bytes for properties structure.\n", BufferSize);
		goto cleanup;
	}

	ZeroMemory(pSystemSessionProperties, BufferSize);
	pSystemSessionProperties->Wnode.BufferSize = BufferSize;
	pSystemSessionProperties->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
	pSystemSessionProperties->Wnode.ClientContext = 1; //QPC clock resolution
	pSystemSessionProperties->Wnode.Guid = myGuid;
	pSystemSessionProperties->LogFileMode = EVENT_TRACE_FILE_MODE_CIRCULAR | PROCESS_TRACE_MODE_REAL_TIME;
	pSystemSessionProperties->EnableFlags = enableFlags;

	pSystemSessionProperties->MaximumFileSize = size;  // 5 MB
	pSystemSessionProperties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
	pSystemSessionProperties->LogFileNameOffset = sizeof(EVENT_TRACE_PROPERTIES) + strlen(KERNEL_LOGGER_NAMEA) + 1;
	StringCbCopyA((LPSTR)((char*)pSystemSessionProperties + pSystemSessionProperties->LogFileNameOffset), strlen(outFileNameSystem) + 1, outFileNameSystem);

	status = StartTraceA((PTRACEHANDLE)&SystemSessionHandle, KERNEL_LOGGER_NAMEA, pSystemSessionProperties);
	if (ERROR_SUCCESS != status) {
		if (ERROR_ALREADY_EXISTS == status)	{
			wprintf(L"The Logger session is already in use.\n");

		}
		else {
			wprintf(L"StartTraceA() failed with %lu\n", status);
		}

	}
	EnableTraceEx2(SystemSessionHandle, &SystemTraceControlGuid, EVENT_CONTROL_CODE_ENABLE_PROVIDER, TRACE_LEVEL_INFORMATION, 1, 0, 0, NULL);

	traceLogfile.LoggerName = KERNEL_LOGGER_NAMEA;
	traceLogfile.ProcessTraceMode = (PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD | PROCESS_TRACE_MODE_RAW_TIMESTAMP);
	traceLogfile.EventRecordCallback = IPCEventRecordCallback;
	SystemConsumerHandle = OpenTraceA(&traceLogfile);
	if (SystemConsumerHandle == INVALID_PROCESSTRACE_HANDLE) {
		printf("OpenTraceA() failed with %lu\n", GetLastError());
	}
	else {
		printf("OpenTraceA succeeded, spawning thread!\n");
		ThreadHandle = CreateThread(0, 0, Win32TracingThread, &SystemConsumerHandle, 0, &ThreadID);
		CloseHandle(ThreadHandle);
		ThreadHandle = NULL;
	}

	///////////////////// Activation des autres dans un 2nd temps

	sprintf_s(titi, 200, "WinPactCustomEventHandler%x%x", __rdtsc(), GetCurrentProcessId());

	BufferSize = 0xF4000;
	pSessionProperties = (EVENT_TRACE_PROPERTIES*)malloc(BufferSize);
	if (NULL == pSessionProperties)
	{
		wprintf(L"Unable to allocate %d bytes for properties structure.\n", BufferSize);
		goto cleanup;
	}

	// d'abord, DBG_COM_RUNDOWNINSTRUMENTATION_GUID

	ZeroMemory(pSessionProperties, BufferSize);
	pSessionProperties->Wnode.BufferSize = BufferSize;
	pSessionProperties->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
	pSessionProperties->Wnode.ClientContext = 1; //QPC clock resolution
	pSessionProperties->Wnode.Guid = myGuid;
	pSessionProperties->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
	pSessionProperties->MaximumBuffers = 16;
	pSessionProperties->MinimumBuffers = 4;
	pSessionProperties->BufferSize = 256000;
	pSessionProperties->FlushTimer = 1;
	pSessionProperties->EnableFlags = enableFlags;

	pSessionProperties->MaximumFileSize = size;  // 5 MB
	pSessionProperties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
	pSessionProperties->LogFileNameOffset = sizeof(EVENT_TRACE_PROPERTIES) + strlen(titi) + 1;
	StringCbCopyA((LPSTR)((char*)pSessionProperties + pSessionProperties->LogFileNameOffset), strlen(outFileName) + 1, outFileName);

	status = StartTraceA((PTRACEHANDLE)&SessionHandle, titi, pSessionProperties);
	if (ERROR_SUCCESS != status) {
		if (ERROR_ALREADY_EXISTS == status)	{
			wprintf(L"The Logger session 2 is already in use.\n");
		}
		else {
			wprintf(L"StartTraceA() 2 failed with %lu\n", status);
		}

		goto cleanup;
	}


	// puis les autres
	EnableTraceEx2(SessionHandle, &DBG_COM_RUNDOWNINSTRUMENTATION_GUID, EVENT_CONTROL_CODE_ENABLE_PROVIDER, TRACE_LEVEL_VERBOSE, 0, 0, 0, NULL);
	EnableTraceEx2(SessionHandle, &DBG_RPC_GUID, EVENT_CONTROL_CODE_ENABLE_PROVIDER, TRACE_LEVEL_VERBOSE, 0, 0, 0, NULL);
	EnableTraceEx2(SessionHandle, &KERNEL_FILE_GUID, EVENT_CONTROL_CODE_ENABLE_PROVIDER, TRACE_LEVEL_VERBOSE, 0, 0, 0, NULL);
	EnableTraceEx2(SessionHandle, &DBG_RPC_EVENTS_GUID, EVENT_CONTROL_CODE_ENABLE_PROVIDER, TRACE_LEVEL_VERBOSE, 0, 0, 0, NULL);
	EnableTraceEx2(SessionHandle, &SMB_CLIENT_GUID, EVENT_CONTROL_CODE_ENABLE_PROVIDER, TRACE_LEVEL_VERBOSE, 0, 0, 0, NULL);
	


	traceLogfile.LoggerName = titi;
	traceLogfile.ProcessTraceMode = (PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD | PROCESS_TRACE_MODE_RAW_TIMESTAMP);
	traceLogfile.EventRecordCallback = IPCEventRecordCallback;
	ConsumerHandle = OpenTraceA(&traceLogfile);
	if (ConsumerHandle == INVALID_PROCESSTRACE_HANDLE) {
		printf("OpenTraceA() 2 failed with %lu\n", GetLastError());
	}
	else {
		printf("OpenTraceA 2 succeeded, spawning thread!\n");
		ThreadHandle = CreateThread(0, 0, Win32TracingThread, &ConsumerHandle, 0, &ThreadID);
		CloseHandle(ThreadHandle);
		ThreadHandle = NULL;
	}



	///////////////////// Wait events
	if (secondsToWait != 0)
		Sleep(1000 * secondsToWait);
	else {
		printf("Appuyez sur une touche pour arreter la capture\n");
		_getch();
	}

cleanup:

	if (SystemConsumerHandle) {
		status = ControlTraceA(SystemConsumerHandle, KERNEL_LOGGER_NAMEA, pSystemSessionProperties, EVENT_TRACE_CONTROL_STOP);
		if (ERROR_SUCCESS != status) {
			wprintf(L"ControlTrace(SystemConsumerHandle, stop) failed with %lu\n", status);
		}
	}

	if (SystemSessionHandle) {
		status = ControlTraceA(SystemSessionHandle, KERNEL_LOGGER_NAMEA, pSystemSessionProperties, EVENT_TRACE_CONTROL_STOP);
		if (ERROR_SUCCESS != status) {
			wprintf(L"ControlTrace(SystemSessionHandle, stop) failed with %lu\n", status);
		}
	}

	if (ConsumerHandle) {
		status = ControlTraceA(ConsumerHandle, titi, pSessionProperties, EVENT_TRACE_CONTROL_STOP);
		if (ERROR_SUCCESS != status) {
			wprintf(L"ControlTrace(ConsumerHandle, stop) failed with %lu\n", status);
		}
	}

	if (SessionHandle) {
		status = ControlTraceA(SessionHandle, titi, pSessionProperties, EVENT_TRACE_CONTROL_STOP);
		if (ERROR_SUCCESS != status) {
			wprintf(L"ControlTrace(SessionHandle, stop) failed with %lu\n", status);
		}
	}

	if (pSessionProperties)
		free(pSessionProperties);

	if (pSystemSessionProperties)
		free(pSystemSessionProperties);


}



/***************************************************************************
***************************************************************************
***************************************************************************

EVTX DUMPS

***************************************************************************
***************************************************************************
***************************************************************************/


static void WINAPI EventRecordCallback(EVENT_RECORD *EventRecord)
{
	EVENT_HEADER &Header = EventRecord->EventHeader;
	ULONG c = 0;
	PEVENT_HEADER_EXTENDED_DATA_ITEM ptr = NULL;

	// Process event here.
	printf("Event received!\n");
	printf("\tProcessID: %d\n", Header.ProcessId);
	printf("\tThreadId: %d\n", Header.ThreadId);
	printf("\tProviderID: {%x-%x-%x-%x%x%x%x%x%x%x%x}\n",
		Header.ProviderId.Data1,
		Header.ProviderId.Data2,
		Header.ProviderId.Data3,
		Header.ProviderId.Data4[0],
		Header.ProviderId.Data4[1],
		Header.ProviderId.Data4[2],
		Header.ProviderId.Data4[3],
		Header.ProviderId.Data4[4],
		Header.ProviderId.Data4[5],
		Header.ProviderId.Data4[6],
		Header.ProviderId.Data4[7]);
	if (Header.EventProperty == EVENT_HEADER_PROPERTY_XML)
		printf("\tEventProperty: EVENT_HEADER_PROPERTY_XML\n");
	if (Header.EventProperty == EVENT_HEADER_PROPERTY_FORWARDED_XML)
		printf("\tEventProperty: EVENT_HEADER_PROPERTY_FORWARDED_XML\n");
	if (Header.EventProperty == EVENT_HEADER_PROPERTY_LEGACY_EVENTLOG)
		printf("\tEventProperty: EVENT_HEADER_PROPERTY_LEGACY_EVENTLOG\n");
	printf("\tTimestamp: %x\n", Header.TimeStamp.QuadPart);
	printf("\tDescriptor.ID: %d\n", Header.EventDescriptor.Id);
	printf("\tDescriptor.Version: %d\n", Header.EventDescriptor.Version);
	printf("\tDescriptor.Channel: %d\n", Header.EventDescriptor.Channel);
	printf("\tDescriptor.Level: %d\n", Header.EventDescriptor.Level);
	printf("\tDescriptor.Version: %d\n", Header.EventDescriptor.Version);
	printf("\tDescriptor.Opcode: %d\n", Header.EventDescriptor.Opcode);
	printf("\tDescriptor.Task: %d\n", Header.EventDescriptor.Task);
	printf("\tExtendedDataCount: %x\n", EventRecord->ExtendedDataCount);
	if (EventRecord->ExtendedDataCount != 0) {
		ptr = EventRecord->ExtendedData;
		printf("\tExtendedData\n");
		for (c = 0; c < EventRecord->ExtendedDataCount; c++) {
			if (ptr[c].ExtType == EVENT_HEADER_EXT_TYPE_RELATED_ACTIVITYID)
				printf("\t\tEVENT_HEADER_EXT_TYPE_RELATED_ACTIVITYID\n");
			else if (ptr[c].ExtType == EVENT_HEADER_EXT_TYPE_SID)
				printf("\t\tEVENT_HEADER_EXT_TYPE_SID\n");
			else if (ptr[c].ExtType == EVENT_HEADER_EXT_TYPE_TS_ID)
				printf("\t\tEVENT_HEADER_EXT_TYPE_TS_ID\n");
			else if (ptr[c].ExtType == EVENT_HEADER_EXT_TYPE_INSTANCE_INFO)
				printf("\t\tEVENT_HEADER_EXT_TYPE_INSTANCE_INFO\n");
			else if (ptr[c].ExtType == EVENT_HEADER_EXT_TYPE_STACK_TRACE32)
				printf("\t\tEVENT_HEADER_EXT_TYPE_STACK_TRACE32\n");
			else if (ptr[c].ExtType == EVENT_HEADER_EXT_TYPE_STACK_TRACE64)
				printf("\t\tEVENT_HEADER_EXT_TYPE_STACK_TRACE64\n");
			else if (ptr[c].ExtType == EVENT_HEADER_EXT_TYPE_EVENT_SCHEMA_TL)
				printf("\t\tEVENT_HEADER_EXT_TYPE_EVENT_SCHEMA_TL\n");
			else if (ptr[c].ExtType == EVENT_HEADER_EXT_TYPE_PROV_TRAITS)
				printf("\t\tEVENT_HEADER_EXT_TYPE_PROV_TRAITS\n");
			else if (ptr[c].ExtType == EVENT_HEADER_EXT_TYPE_PEBS_INDEX)
				printf("\t\tEVENT_HEADER_EXT_TYPE_PEBS_INDEX\n");
			else if (ptr[c].ExtType == EVENT_HEADER_EXT_TYPE_PSM_KEY)
				printf("\t\tEVENT_HEADER_EXT_TYPE_PSM_KEY\n");
			else if (ptr[c].ExtType == EVENT_HEADER_EXT_TYPE_PMC_COUNTERS)
				printf("\t\tEVENT_HEADER_EXT_TYPE_PMC_COUNTERS\n");
			else if (ptr[c].ExtType == EVENT_HEADER_EXT_TYPE_PROCESS_START_KEY)
				printf("\t\tEVENT_HEADER_EXT_TYPE_PROCESS_START_KEY\n");
			else
				printf("\t\tUNDEFINED: %x\n", ptr[c].ExtType);
		}
	}
	printf("\tUser data length: %x\n", EventRecord->UserDataLength);
	DumpHex(EventRecord->UserData, EventRecord->UserDataLength);
	printf("\n");

}

static BOOL WINAPI StaticBufferEventCallback(PEVENT_TRACE_LOGFILEA buf)
{
	printf("StaticBufferEventCallback\n");
	return TRUE;
}


void DumpEvents(GUID providerGuid, ULONG secondsToWait, char* outFileName, ULONG size, ULONG enableFlags) {
	ULONG status = ERROR_SUCCESS;
	TRACEHANDLE SessionHandle = 0, ConsumerHandle= 0;
	EVENT_TRACE_PROPERTIES* pSessionProperties = NULL;
	EVENT_TRACE_LOGFILEA traceLogfile = { 0 };
	ULONG BufferSize = 0;
	char titi[200];
	DWORD ThreadID = 0;
	HANDLE ThreadHandle = NULL;

	// provider name
	if (providerGuid == SystemTraceControlGuid)
		sprintf_s(titi, 200, "%s", KERNEL_LOGGER_NAMEA);
	else
		sprintf_s(titi, 200, "WinPactCustomEventHandler%x%x", __rdtsc(), GetCurrentProcessId());

	// allocation du session properties
	BufferSize = sizeof(EVENT_TRACE_PROPERTIES) + strlen(outFileName) + 1 + strlen(titi) + 1;
	pSessionProperties = (EVENT_TRACE_PROPERTIES*)malloc(BufferSize);
	if (NULL == pSessionProperties)
	{
		wprintf(L"Unable to allocate %d bytes for properties structure.\n", BufferSize);
		goto cleanup;
	}

	// setup des properties
	ZeroMemory(pSessionProperties, BufferSize);
	pSessionProperties->Wnode.BufferSize = BufferSize;
	pSessionProperties->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
	pSessionProperties->Wnode.ClientContext = 1; //QPC clock resolution
	pSessionProperties->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
	pSessionProperties->MaximumBuffers = 16;
	pSessionProperties->MinimumBuffers = 4;
	pSessionProperties->BufferSize = 256000;
	pSessionProperties->FlushTimer = 1;
	pSessionProperties->MaximumFileSize = size;
	pSessionProperties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
	pSessionProperties->LogFileNameOffset = sizeof(EVENT_TRACE_PROPERTIES) + strlen(titi) + 1;

	if (providerGuid == SystemTraceControlGuid) {
		pSessionProperties->EnableFlags = enableFlags;
		pSessionProperties->Wnode.Guid = SystemTraceControlGuid;
	}

	StringCbCopyA((LPSTR)((char*)pSessionProperties + pSessionProperties->LogFileNameOffset), strlen(outFileName) + 1, outFileName);


	// activation de la trace, qui va être vide puisqu'aucun provider n'est actif
	status = StartTraceA((PTRACEHANDLE)&SessionHandle, titi, pSessionProperties);
	if (ERROR_SUCCESS != status) {
		if (ERROR_ALREADY_EXISTS == status)	{
			wprintf(L"The Logger session is already in use.\n");
		}
		else {
			wprintf(L"EnableTrace() failed with %lu\n", status);
		}

		goto cleanup;
	}

	traceLogfile.LoggerName = titi;
	traceLogfile.ProcessTraceMode = (PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD | PROCESS_TRACE_MODE_RAW_TIMESTAMP);
	traceLogfile.EventRecordCallback = EventRecordCallback;
	traceLogfile.BufferCallback = (PEVENT_TRACE_BUFFER_CALLBACKA)StaticBufferEventCallback;
	ConsumerHandle = OpenTraceA(&traceLogfile);
	if (ConsumerHandle == INVALID_PROCESSTRACE_HANDLE) {
		printf("OpenTraceA() failed with %lu\n", GetLastError());
	}
	else {
		printf("OpenTraceA succeeded, spawning thread!\n");
		ThreadHandle = CreateThread(0, 0, Win32TracingThread, &ConsumerHandle, 0, &ThreadID);
		CloseHandle(ThreadHandle);
		ThreadHandle = NULL;
	}


	

	status = EnableTraceEx2(SessionHandle, &providerGuid, EVENT_CONTROL_CODE_ENABLE_PROVIDER, TRACE_LEVEL_VERBOSE, 0, 0, 0, NULL);
	if (ERROR_SUCCESS != status) {
		wprintf(L"EnableTrace() failed with %lu\n", status);
	}

	if (secondsToWait == 0) {
		printf("Hit any key so stop the session.\n");
		_getch();
	}
	else
		Sleep(1000 * secondsToWait);

cleanup:

	if (ConsumerHandle) {
		status = ControlTraceA(ConsumerHandle, titi, pSessionProperties, EVENT_TRACE_CONTROL_STOP);
		if (ERROR_SUCCESS != status) {
			wprintf(L"ControlTrace(ConsumerHandle, stop) failed with %lu\n", status);
		}
	}

	if (SessionHandle) {
		status = ControlTraceA(SessionHandle, titi, pSessionProperties, EVENT_TRACE_CONTROL_STOP);
		if (ERROR_SUCCESS != status) {
			wprintf(L"ControlTrace(SessionHandle, stop) failed with %lu\n", status);
		}
	}

	if (pSessionProperties)
		free(pSessionProperties);

}





int main(int argc, char** argv) {

	if (argc == 3 && !_stricmp(argv[1],"--ipctracer")) {
		IPCTracer(atoi(argv[2]));
		return 0;

	}

	if (argc < 5) {

		printf("Usage : %s {guid} <seconds> <maxfilesizeinMB> <output.etl> (-system)   OR    --ipctracer <seconds>\n"
			"Use the -s setting if your guid is a system one (see the https://docs.microsoft.com/en-us/windows/desktop/etw/event-trace-properties EnableFlags values)\n"
			"Examples:\n"
			"%s {12345678-1234-1234-1212121212121212} 10 5 out.etl\n"
			"%s --ipctracer 5\n"
			"%s 100000 10 5 system_alpc_capture.etl -system\n", argv[0], argv[0], argv[0], argv[0]);
		return 1;
	}

	char* guidstr = argv[1];
	char* secondsstr = argv[2];
	char* maxsizestr = argv[3];
	char* outputfile = argv[4];
	WCHAR guidStrW[0x40];

	ULONG seconds = atoi(secondsstr);
	ULONG maxsize = atoi(maxsizestr);
	GUID myGuid = { 0 };
	ULONG flags = 0;


	if (argc > 5) {
		if (!_strnicmp(argv[5], "-system", 7)) {
			flags = strtoul(guidstr, NULL, 16);
			myGuid = SystemTraceControlGuid;
		}
	}

	if (myGuid == SystemTraceControlGuid) {

		printf("System session starting:\n"
			"\tseconds: %d\n"
			"\toutput file: %s\n"
			"\tmax file size: %d MB\n"
			"\tflags: 0x%x\n\n", seconds, outputfile, maxsize, flags);
	}
	else {

		MultiByteToWideChar(CP_UTF8, 0, guidstr, -1, guidStrW, 0x40);
		if (CLSIDFromString(guidStrW, &myGuid) != NOERROR) {
			printf("CLSIDFromString failed!\n");
			return -1;
		}

		printf("Session starting:\n"
				"\tseconds: %d\n"
				"\toutput file: %s\n"
				"\tmax file size: %d MB\n"
				"\tProviderID: {%x-%x-%x-%x%x%x%x%x%x%x%x}\n\n", seconds, outputfile, maxsize,
				myGuid.Data1,
				myGuid.Data2,
				myGuid.Data3,
				myGuid.Data4[0],
				myGuid.Data4[1],
				myGuid.Data4[2],
				myGuid.Data4[3],
				myGuid.Data4[4],
				myGuid.Data4[5],
				myGuid.Data4[6],
				myGuid.Data4[7]);
		
	}

	DumpEvents(myGuid, seconds, outputfile, maxsize, flags);
	return 0;
}
