#include "hook_revealer.h"

void analysis::analyseProcesses()
{
	PROCESSENTRY32 current;
	HANDLE list;

	current.dwSize = sizeof(PROCESSENTRY32);
	
	list = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if(!list)
	{
		printf(" [-] Could not list active processes.\n");
		return;
	}
	if(Process32First(list, &current))
	{
		currentPid=current.th32ProcessID;
		currentProcessName=current.szExeFile;
		process_analysis();

		while(Process32Next(list, &current))
		{
			currentPid=current.th32ProcessID;
			currentProcessName=current.szExeFile;
			process_analysis();
		}
	}
	else
	{
		printf(" [-] Could not list active processes.\n");
	}

	CloseHandle(list);
}