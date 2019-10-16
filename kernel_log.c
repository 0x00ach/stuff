NTSTATUS FastLog(
	PVOID data,
	ULONGLONG size
)
{
	HANDLE fileHandle;
	OBJECT_ATTRIBUTES attr;
	IO_STATUS_BLOCK statusBlock;
	NTSTATUS status;
	UNICODE_STRING fileName;
	LARGE_INTEGER byteOffset;
	UCHAR write_data[0x200];

	if (KeGetCurrentIrql() != PASSIVE_LEVEL)
		return STATUS_INVALID_DEVICE_STATE;

	if (data == NULL)
		return STATUS_INVALID_PARAMETER;
	if (size > 0x200)
		size = 0x200;

	RtlZeroMemory(write_data, 0x200);
	RtlCopyMemory(write_data, data, size);

	RtlInitUnicodeString(&fileName, L"\\DosDevices\\C:\\fastlog.txt");

	InitializeObjectAttributes(&attr,
		&fileName,
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
		NULL, NULL);

	status = ZwCreateFile(&fileHandle,
		FILE_WRITE_DATA,
		&attr,
		&statusBlock, 0,
		FILE_ATTRIBUTE_NORMAL, 0,
		FILE_SUPERSEDE,
		FILE_NON_DIRECTORY_FILE | FILE_NO_INTERMEDIATE_BUFFERING,
		NULL, 0);

	if (!NT_SUCCESS(status))
	{
		if (NT_SUCCESS(RtlStringCbPrintfA((NTSTRSAFE_PSTR)write_data, 0x200, (NTSTRSAFE_PCSTR) "[!] FASTDBG:ZwWriteFile: 0x%I64x (%I64x)\r\n", status, statusBlock.Status))) {
			TdHeLog(write_data);
		}
		return status;
	}

	byteOffset.QuadPart = 0;
	status = ZwWriteFile(fileHandle,
		NULL, NULL, NULL,
		&statusBlock,
		(PVOID)write_data,
		0x200,
		&byteOffset,
		NULL
	);
	if (!NT_SUCCESS(status))
		if (NT_SUCCESS(RtlStringCbPrintfA((NTSTRSAFE_PSTR)write_data, 0x200, (NTSTRSAFE_PCSTR) "[!] FASTDBG:ZwWriteFile: 0x%I64x (%I64x)\r\n", status, statusBlock.Status))) {
			TdHeLog(write_data);
		}

	ZwClose(fileHandle);
	return status;
}
