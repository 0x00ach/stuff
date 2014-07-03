#include "hook_revealer.h"


void analysis::pebAnalysisAndLoadModules()
{
	PROCESS_BASIC_INFORMATION procinfo;
	DWORD baseAddr = 1;
	ULONG dwSize = 0;
	module* mod = NULL;
	WORD leng = 0;
	DWORD modnameaddr = 0;
	char* nomModuleA = NULL;
	int len = 0;
	DWORD pebAddr = 0;
	BYTE beingDebugged = 0x00;
	DWORD processParameters = 0;
	USHORT lenPathName = 0;
	DWORD imagePathNameAddr = 0;
	WCHAR* pathName = NULL;
	USHORT lenCommandLine = 0;
	DWORD commandLineAddr = 0;
	WCHAR* commandLine = NULL;
	DWORD pLdrData = 0;
	DWORD current = 0;
	WCHAR* nomModule = NULL;

	if(myNtQueryInformationProcess(currentProcessHandle, 0, &procinfo, sizeof(procinfo), &dwSize)!=STATUS_SUCCESS)
	{
		fprintf(currentFile, "602|%d|||NtQueryInformationProcess failed|\n", currentPid);
		return;
	}
	pebAddr=(DWORD)procinfo.PebBaseAddress;
	
	beingDebugged=readB(pebAddr+2);
	if(beingDebugged != 0x0)
		fprintf(currentFile, "301|%d|||true|\n", currentPid);
	else
		fprintf(currentFile, "301|%d|||false|\n", currentPid);

	//PEB -> processParameters
	processParameters=readDw(pebAddr+16);
	if(processParameters == 0)
	{
		fprintf(currentFile, "602|%d|||Bad PEB|\n", currentPid);
		return;
	}
	//processParameters->ImagePathName.len
	lenPathName=readW(processParameters+56);
	if(lenPathName == 0)
		return;

	//processParameters->ImagePathName.buffer
	imagePathNameAddr=readDw(processParameters+60);
	if(imagePathNameAddr == 0)
		return;

	pathName=new WCHAR[lenPathName];
	memset(pathName, 0x00, lenPathName*sizeof(WCHAR));

	if(!readMem(imagePathNameAddr, pathName, lenPathName))
	{
		printf("!");
		fprintf(currentFile, "602|%d|||Could not read memory|\n", currentPid);
	}
	else 
		fwprintf(currentFile, L"401|%d|%s|||\n", currentPid, pathName);

	delete[] pathName; 
	pathName=NULL;

	//processParameters->CommandLine.len
	lenCommandLine = readW(processParameters+64);
	if(lenCommandLine == 0)
	{
		fprintf(currentFile, "602|%d|||Could not read memory|\n", currentPid);
		printf("!");
		return;
	}

	//processParameters->CommandLine.buffer
	commandLineAddr=readDw(processParameters+68);
	if(commandLineAddr == 0)
	{
		fprintf(currentFile, "602|%d|||Could not read memory|\n", currentPid);
		printf("!");
		return;
	}

	commandLine=new WCHAR[lenCommandLine];
	memset(commandLine, 0x00, lenCommandLine*sizeof(WCHAR));

	if(!readMem(commandLineAddr, commandLine, lenCommandLine))
	{
		printf("!");
		fprintf(currentFile, "602|%d|||Could not read memory|\n", currentPid);
	}
	else 
		fwprintf(currentFile, L"402|%d|||%s|\n", currentPid, commandLine);
	delete[] commandLine;
	commandLine=NULL;
	
	//pLdrData = peb -> LoaderData
	pLdrData=readDw(pebAddr+0xC);
	if(pLdrData == 0)
	{
		fprintf(currentFile, "602|%|||Could not read memory|\n", currentPid);
		printf("!");
		return;
	}

	//current = pLdrData.InLoadOrderModuleList.Flink
	current = readDw(pLdrData+12);
	if(current == 0)
	{
		fprintf(currentFile, "602|%d|||Could not read memory|\n", currentPid);
		printf("!");
		return;
	}

	nomModule=new WCHAR[MAX_PATH];

	while(baseAddr != 0)
	{
		baseAddr=readDw(current+24);
		
		if(baseAddr!=0)
		{
			mod=new module();
			mod->baseAddr=0;
			mod->codeAddr=0;
			mod->eatAddr=0;
			mod->endOfCodeAddr=0;
			mod->iatAddr=0;
			mod->moduleFileName=NULL;

			nomModuleA=new char[MAX_PATH];
			memset(nomModule, 0x00, MAX_PATH);
			
			leng=readW(current+44);
			if(leng == 0)
			{
				if(nomModule!=NULL)
				{
					delete[] nomModule;
					nomModule = NULL;
				}
				if(mod != NULL)
				{
					delete mod;
					mod = NULL;
				}
			}
			else
			{
				modnameaddr=readDw(current+48);
				if(modnameaddr == 0)
				{
					if(nomModule!=NULL)
					{
						delete[] nomModule;
						nomModule = NULL;
					}
					if(mod != NULL)
					{
						delete mod;
						mod = NULL;
					}
				}
				else
				{
					readMem(modnameaddr, nomModule, leng);

					wcstombs_s((size_t*)&len,nomModuleA,MAX_PATH,nomModule,MAX_PATH);

					loadedModules=(ppmodule)realloc(loadedModules, sizeof(pmodule)*(nbLoadedModules+1));
					if(loadedModules!=NULL)
					{
						mod->baseAddr=baseAddr;
						mod->moduleFileName=nomModuleA;
						loadedModules[nbLoadedModules]=mod;
						nbLoadedModules++;
					}
					else
					{
						if(mod != NULL)
						{
							delete mod;
							mod=NULL;
						}
					}
				}
			}
		}

		current = readDw(current);
	}
	
	if(nomModule != NULL)
	{
		delete[] nomModule;
		nomModule=NULL;
	}
}

pmodule analysis::gmh(char* name)
{
	for(int i=0; i<nbLoadedModules; i++)
	{
		if(_stricmp(name, loadedModules[i]->moduleFileName)==0)
			return loadedModules[i];
	}
	return NULL;

}
 
void analysis::deleteModules()
{
	if(nbLoadedModules>0 && loadedModules!=NULL)
	{
		for(int i=0; i<nbLoadedModules; i++)
		{
			if(loadedModules[i] != NULL)
			{
				if(loadedModules[i]->moduleFileName != NULL)
				{
					delete[] (loadedModules[i]->moduleFileName);
					loadedModules[i]->moduleFileName=NULL;
				}
				delete loadedModules[i];
				loadedModules[i]=NULL;
			}
		}
		free( loadedModules );
		nbLoadedModules=0;
		loadedModules=NULL;
	}
}