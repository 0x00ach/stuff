#include "hook_revealer.h"

void analysis::loadSystem32Dlls()
{
	char* path = NULL;
	WIN32_FIND_DATAA fdata;
	HANDLE fh = NULL;

	nbSys32dllFiles=0;
	sys32dllFiles=NULL;

	//celles là au moins, au cas où...
	sys32dllFiles=(char**)realloc(sys32dllFiles, sizeof(char*)*(nbSys32dllFiles+1));
	sys32dllFiles[nbSys32dllFiles]="kernel32.dll";
	nbSys32dllFiles++;
	sys32dllFiles=(char**)realloc(sys32dllFiles, sizeof(char*)*(nbSys32dllFiles+1));
	sys32dllFiles[nbSys32dllFiles]="ntdll.dll";
	nbSys32dllFiles++;

	path = new char[MAX_PATH];
	GetWindowsDirectory(path, MAX_PATH);
	if(strlen(path) >= MAX_PATH-16)
		return;

	strcat_s(path, MAX_PATH, "\\System32\\*.dll");

	fh = FindFirstFileA(path, &fdata);
	if(!fh)
	{	
		printf(" [-] Could not list system32 flles\n");
		return;
	}

	sys32dllFiles=(char**)realloc(sys32dllFiles, sizeof(char*)*(nbSys32dllFiles+1));
	sys32dllFiles[nbSys32dllFiles]=fdata.cFileName;
	nbSys32dllFiles++;


	while(FindNextFileA(fh, &fdata))
	{
		sys32dllFiles=(char**)realloc(sys32dllFiles, sizeof(char*)*(nbSys32dllFiles+1));
		sys32dllFiles[nbSys32dllFiles]=fdata.cFileName;
		nbSys32dllFiles++;
	}

	CloseHandle(fh);
}

bool analysis::isSystem32File(char* nom_module)
{
	for(int i=0; i<nbSys32dllFiles; i++)
		if(!_stricmp(nom_module, sys32dllFiles[i]))
			return true;

	return false;
}