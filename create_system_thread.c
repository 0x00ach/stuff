HANDLE hThread;
SHORT thread_status;

VOID StopSysthread()
{
	PKTHREAD oThread;

	if (hThread != NULL && thread_status == 1)
	{
		if (InterlockedCompareExchange16(&thread_status, 2, 1) == 1)
		{
			if (NT_SUCCESS(ObReferenceObjectByHandle(hThread, 0, 0, KernelMode, &oThread, 0)))
			{
				KeWaitForSingleObject(oThread, Executive, KernelMode, FALSE, NULL);
				ObDereferenceObject(oThread);
			}
		}
	}
	if (hThread != NULL)
	{
		ZwClose(hThread);
		hThread = NULL;
	}
}

NTSTATUS StartSysThread()
{
    NTSTATUS status;
	OBJECT_ATTRIBUTES oAttr;

	thread_status = 0;
	hThread = NULL;
	
	InitializeObjectAttributes(&oAttr, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
	status = PsCreateSystemThread(&hThread, THREAD_ALL_ACCESS, &oAttr, NULL, NULL, (PKSTART_ROUTINE)&threadProc, NULL);
	
    return status;
}

NTSTATUS threadProc()
{
	if (InterlockedCompareExchange16(&thread_status, 1, 0) == 2)
		PsTerminateSystemThread(STATUS_SUCCESS);
		
	// do something

	// place this anywhere you want
	if (thread_status == 2)
		PsTerminateSystemThread(STATUS_SUCCESS);

	// do something
	
	PsTerminateSystemThread(STATUS_SUCCESS);
}
