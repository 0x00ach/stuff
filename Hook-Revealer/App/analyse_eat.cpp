#include "hook_revealer.h"

//est-ce que cette module.fonction est forwardée d'après son export ?
bool analysis::isForwardedFunction(char* name, pmodule mod)
{
	for(int i=0; i<nbforwardeds; i++)
		if(_stricmp(name, forwardeds[i]->functionName)==0)
			if(mod==forwardeds[i]->moduleFunc)
				return true;
	
	return false;

}

//analyse de l'export address table du module
void analysis::analyse_eat(pmodule mod)
{
	DWORD eatAddr=mod->eatAddr;
	DWORD npt = 0;
	DWORD fpt = 0;
	DWORD opt = 0;
	DWORD numberOfNames = 0;
	DWORD funcAddr = 0;
	char* name =  NULL;
	DWORD nameAddr=0;
	char* nameWrap = NULL;
	WORD currentOrdinal=0x0;
	pforwarded_eat_function temp_p;
	unsigned int i, j, k;

	if(eatAddr==mod->baseAddr)
		return;

	//parsing de l'EAT (address of names, functions & ordinals)
	npt = readDw(eatAddr + 0x20)+mod->baseAddr;
	fpt = readDw(eatAddr + 0x1C)+mod->baseAddr;
	opt = readDw(eatAddr + 0x24)+mod->baseAddr;

	//number of names
	numberOfNames = readDw(eatAddr + 0x18);
	
	for(int i=0; i<numberOfNames; i++)
	{
		//npt est un tableau de DWORD, et sizeof(DWORD)==4
		nameAddr=readDw(npt+(i*4))+mod->baseAddr;

		if(nameAddr!=0)
		{
			name=new char[MAX_PATH];
			memset(name, 0x00, MAX_PATH);
			j=0;
			//on lit tant qu'on trouve pas de 0x00 et qu'on a pas trop lu
			while(readB(nameAddr+j)!=0x00 && j<MAX_PATH)
			{
				name[j]=readB(nameAddr+j);
				j++;
			}
			//ordinal
			currentOrdinal=readW(opt+(i*2));

			funcAddr=readDw(fpt+(currentOrdinal*4))+mod->baseAddr;
			if(funcAddr!=mod->baseAddr)
			{
				if(funcAddr < mod->endOfEatAddr && funcAddr > mod->eatAddr)
				{
					//fonction exportée
					forwardeds=(ppforwarded_eat_function)realloc(forwardeds, (nbforwardeds+1)*sizeof(pforwarded_eat_function));
					if(forwardeds!=NULL)
					{
						temp_p=new forwarded_eat_function;
						temp_p->functionName=name;
						temp_p->moduleFunc=mod;
						forwardeds[nbforwardeds]=temp_p;

						nameWrap=new char[MAX_PATH];
						memset(nameWrap, 0x00, MAX_PATH);
						k=0;
						while(readB(funcAddr+k)!=0x00 && k<MAX_PATH)
						{
							nameWrap[k]=readB(funcAddr+k);
							k++;
						}

						fprintf(currentFile, "122|%d|%s||%s|%s\n", currentPid, mod->moduleFileName, name, nameWrap);
						delete[] nameWrap;
						nbforwardeds++;
					}
				}
				else
				{
					if(funcAddr!=0x00)
					{
						if(funcAddr < mod->codeAddr || funcAddr > mod->endOfCodeAddr)
						{
							fprintf(currentFile, "121|%d|%s||%s|%s.0x%x\n", currentPid, mod->moduleFileName, name, whosthisaddr(funcAddr), funcAddr);
						}
						else
						{
							detect_inline_hook(mod, name, funcAddr);
						}
					}
					//on n'en a plus besoin
					delete[] name;
				}
			}
			else
				delete[] name;
		}
	}
}