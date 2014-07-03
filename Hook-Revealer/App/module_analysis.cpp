#include "hook_revealer.h"

void analysis::analyse_modules()
{
	if(nbLoadedModules!=0 && loadedModules!=NULL)
	{
		for(int i=0; i<nbLoadedModules; i++)
		{
			fprintf(currentFile, "601|%d|%s||0x%x|\n", currentPid, loadedModules[i]->moduleFileName, loadedModules[i]->baseAddr);
			module_analysis(loadedModules[i]);
		}
		printf("-");
		for(int i=0; i<nbLoadedModules; i++)
		{
			module_iat_analysis(loadedModules[i]);
		}
		printf("-");
	}
}

char* analysis::whosthisaddr(DWORD addr)
{
	if(nbLoadedModules!=0 && loadedModules!=NULL)
	{
		for(int i=0; i<nbLoadedModules; i++)
		{
			if(addr >= loadedModules[i]->codeAddr && addr <= loadedModules[i]->endOfModule)
				return loadedModules[i]->moduleFileName;
		}
	}

	return "UNKNOWN";
}

void analysis::module_analysis(pmodule mod)
{
	DWORD peHeaderOffset = 0;
	DWORD peHeaderAddr = 0;


	//sys32 file ?
	if(isSystem32File(mod->moduleFileName))
		analyse_system32(mod);

	//parsing du PE
	peHeaderOffset=readDw(mod->baseAddr+0x3C);
	if(peHeaderOffset == 0)
	{
		fprintf(currentFile, "602|%d|||Cannot read memory|\n", currentPid);
		return;
	}
	peHeaderAddr=peHeaderOffset+mod->baseAddr;

	
	//DLL, analyse de l'eat
	mod->codeAddr=readDw(peHeaderAddr + 0x2C) + mod->baseAddr;
	mod->endOfCodeAddr=readDw(peHeaderAddr + 0x1C) + mod->codeAddr;
	mod->eatAddr=readDw(peHeaderAddr + 0x78) + mod->baseAddr;
	mod->endOfEatAddr=readDw(peHeaderAddr + 0x7C) + mod->eatAddr;
	mod->iatAddr=readDw(peHeaderAddr + 0x80) + mod->baseAddr;
	mod->iatSize=readDw(peHeaderAddr + 0x84);
	mod->endOfModule=readDw(peHeaderAddr + 0x50)+ mod->baseAddr;
	
	if((readW(peHeaderAddr+0x16)&0xF000) == 0x2000)
		mod->isDll=true;
	else
		mod->isDll=false;

	if(mod->endOfEatAddr != 0x0 && mod->isDll)
		analyse_eat(mod);
	

}