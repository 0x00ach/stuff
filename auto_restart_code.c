typedef VOID(WINAPI* nullProc)();
ULONG functionRunning;
nullProc restartFunction;

DWORD __stdcall functionInit(PVOID osef) {
	_Unreferenced_parameter_ osef;

	if (InterlockedCompareExchange(&functionRunning, GetCurrentThreadId(), 0) != 0) 
		return 1;

	restartFunction();
	return 0;
}

VOID stopThreadAndRestart() {
	ULONG tid;

	functionRunning = 0;

	CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)functionInit, NULL, 0, &tid);

	CoUninitialize();
	ExitThread(0);
}


LONG CALLBACK VectoredHandler(
	_In_ PEXCEPTION_POINTERS ExceptionInfo
	) {
	ULONG threadId;

	threadId = GetCurrentThreadId();
	/*
	xcpt_print_acquire();
	printf("\t[!] Thread %x crashed! (0x%x at 0x%p)\n", threadId, ExceptionInfo->ExceptionRecord->ExceptionCode, ExceptionInfo->ExceptionRecord->ExceptionAddress);
	xcpt_xprint_release();
	*/
#ifdef _WIN64
	if (IsBadWritePtr((PVOID)(ExceptionInfo->ContextRecord->Rsp - 0x100), 0x100)) {
		if (IsBadWritePtr((PVOID)ExceptionInfo->ContextRecord->Rsp, 1))
			ExceptionInfo->ContextRecord->Rsp = (ULONGLONG)VirtualAlloc(NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE) / 2;
		else {
			ExceptionInfo->ContextRecord->Rsp = ExceptionInfo->ContextRecord->Rsp + 0x200;
			if (IsBadWritePtr((PVOID)(ExceptionInfo->ContextRecord->Rsp - 0x100), 0x100))
				ExceptionInfo->ContextRecord->Rsp = (ULONGLONG)VirtualAlloc(NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE) / 2;
		}
	}

	if (functionRunning == threadId) {
		ExceptionInfo->ContextRecord->Rip = (ULONGLONG)stopThreadAndRestart;
	}
	else
		ExceptionInfo->ContextRecord->Rip = (ULONGLONG)ExitThread;

	
	ExceptionInfo->ContextRecord->Rax = 0;
	ExceptionInfo->ContextRecord->Rbx = 0;
	ExceptionInfo->ContextRecord->Rcx = 0;
	ExceptionInfo->ContextRecord->Rdx = 0;
	ExceptionInfo->ContextRecord->R8 = 0;
	ExceptionInfo->ContextRecord->R9 = 0;
	ExceptionInfo->ContextRecord->R10 = 0;
	ExceptionInfo->ContextRecord->R11 = 0;
	ExceptionInfo->ContextRecord->R12 = 0;
	ExceptionInfo->ContextRecord->R13 = 0;
	ExceptionInfo->ContextRecord->R14 = 0;
	ExceptionInfo->ContextRecord->R15 = 0;
	ExceptionInfo->ContextRecord->Rsi = 0;
	ExceptionInfo->ContextRecord->Rdi = 0;
	ExceptionInfo->ContextRecord->Rbp = ExceptionInfo->ContextRecord->Rsp;
	ExceptionInfo->ContextRecord->EFlags = 0;
#else
	if (IsBadWritePtr((PVOID)(ExceptionInfo->ContextRecord->Esp - 0x100), 0x100)) {
		if (IsBadWritePtr((PVOID)ExceptionInfo->ContextRecord->Esp, 1))
			ExceptionInfo->ContextRecord->Esp = (ULONGLONG)VirtualAlloc(NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE) / 2;
		else {
			ExceptionInfo->ContextRecord->Esp = ExceptionInfo->ContextRecord->Esp + 0x200;
			if (IsBadWritePtr((PVOID)(ExceptionInfo->ContextRecord->Esp - 0x100), 0x100))
				ExceptionInfo->ContextRecord->Esp = (ULONGLONG)VirtualAlloc(NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE) / 2;
		}
	}

	if (functionRunning == threadId) {
		ExceptionInfo->ContextRecord->Eip = (ULONG)stopThreadAndRestart;
	}
	else
		ExceptionInfo->ContextRecord->Eip = (ULONG)ExitThread;


	ExceptionInfo->ContextRecord->Eax = 0;
	ExceptionInfo->ContextRecord->Ebx = 0;
	ExceptionInfo->ContextRecord->Ecx = 0;
	ExceptionInfo->ContextRecord->Edx = 0;
	ExceptionInfo->ContextRecord->Esi = 0;
	ExceptionInfo->ContextRecord->Edi = 0;
	ExceptionInfo->ContextRecord->Ebp = ExceptionInfo->ContextRecord->Esp;
	ExceptionInfo->ContextRecord->EFlags = 0;

#endif
	return EXCEPTION_CONTINUE_EXECUTION;
}

VOID runFunctionInfinite(PVOID functionAddr) {
	ULONG tid;
	// reset
	functionRunning = 0;
	AddVectoredExceptionHandler(0, VectoredHandler);
	restartFunction = (nullProc)functionAddr;

	CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)functionInit, NULL, 0, &tid);

	Sleep(INFINITE);

}
