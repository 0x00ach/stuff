#include "hook_revealer.h"

void analysis::analyse_system32(pmodule mod)
{
	DWORD peOffset=readDw(mod->baseAddr+0x3C);
	DWORD peEnd = 0;
	DWORD len = 0;
	PWSTR systempath = NULL;
	PWSTR modnamew = NULL;
	PWSTR filepath = NULL;
	int size=0;
	PBYTE fileBytes = NULL;
	PBYTE memBytes = NULL;
	int nbBytesRead = 0;

	peOffset=peOffset + mod->baseAddr;

	peEnd=peOffset+0xF4;
	len=peEnd - mod->baseAddr;

	// construction du path en WCHAR
	systempath=L"\\Systemroot\\System32\\";
	modnamew=new WCHAR[55];
	memset(modnamew, 0x00, 55);
	filepath=new WCHAR[MAX_PATH];
	memset(filepath, 0x00, MAX_PATH);
	
	mbstowcs_s((size_t*)&size, modnamew, 50, mod->moduleFileName, 50);
	wcscat_s(filepath, MAX_PATH, systempath);
	wcscat_s(filepath, MAX_PATH, modnamew);

	if(modnamew != NULL)
	{
		delete[] modnamew;
		modnamew=NULL;
	}
	//nombre de bytes : 0 - fin de l'entête PE (sauf les sections)

	//bytes lues
	fileBytes=new BYTE[len];
	memBytes=new BYTE[len];

	readMem(mod->baseAddr, memBytes, len);

	// lecture du fichier
	if(readFile(filepath, fileBytes, len, 0, &nbBytesRead))
	{
		if(filepath != NULL)
		{
			delete[] filepath;
			filepath=NULL;
		}

		for(DWORD i=0; i<len; i++)
		{
			if(*(fileBytes+i) != *(memBytes+i))
			{
				fprintf(currentFile, "501|%d|%s||%s|\n", currentPid, mod->moduleFileName, filepath);
				if(fileBytes != NULL)
				{
					delete[] fileBytes;
					fileBytes=NULL;
				}
				if(memBytes != NULL)
				{
					delete[] memBytes;
					memBytes=NULL;
				}
				return;
			}
		}
	}

	if(fileBytes != NULL)
	{
		delete[] fileBytes;
		fileBytes=NULL;
	}
	if(memBytes != NULL)
	{
		delete[] memBytes;
		memBytes=NULL;
	}
}