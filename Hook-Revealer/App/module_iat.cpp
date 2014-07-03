#include "hook_revealer.h"

void analysis::module_iat_analysis(pmodule mod)
{
	DWORD iat = 0;
	DWORD currentEntry = 0;
	DWORD originalsFt = 0;
	DWORD simplesFt = 0;
	DWORD nameImg = 0;
	DWORD funcAddr = 0;
	DWORD modNameAddr=0;
	DWORD modNameOffset=0;
	int i=0;
	unsigned int j = 0;
	unsigned int k = 0;
	char* funcName = NULL;
	char* name = NULL;
	pmodule dest = NULL;
	int nbOfEntries = 0;

	if(mod->iatAddr == mod->baseAddr ) 
		return;

	nbOfEntries = mod->iatSize/ sizeof(IMAGE_IMPORT_DESCRIPTOR) -1;
	
	if( nbOfEntries <= 0)
		return;

	//adresse de l'IAT
	iat = mod->iatAddr;

	modNameOffset = 1;
	while(modNameOffset != 0)
	{
		//IAT = IMAGE_IMPORT_DESCRIPTOR[nbOfEntries]
		//donc current = iat[i]
		currentEntry=iat + (i*sizeof(IMAGE_IMPORT_DESCRIPTOR));

		//IMAGE_IMPORT_DESCRIPTOR.Name (+12)
		modNameOffset=readDw(currentEntry + 12);
		
		if(modNameOffset != 0)
		{

			if(modNameOffset!=0)
			{
				modNameAddr=mod->baseAddr+modNameOffset;

				name=new char[MAX_PATH];
				memset(name, 0x00, MAX_PATH);
				j=0;
				//lecture du nom du module
				while(j!=MAX_PATH && readB(modNameAddr+j)!=0x00)
				{
					name[j]=readB(modNameAddr+j);
					j++;
				}
				dest=gmh(name);

				if(dest!=NULL)
				{
					//IMAGE_IMPORT_DESCRIPTOR.OriginalFirstThunk
					originalsFt=readDw(currentEntry)+mod->baseAddr;
					//IMAGE_IMPORT_DESCRIPTOR.FirstThunk
					simplesFt=readDw(currentEntry + 16)+mod->baseAddr;

					while(readDw(originalsFt)!=0)
					{
						nameImg = readDw(originalsFt)+mod->baseAddr;
						k=0;
						funcName=new char[MAX_PATH];
						memset(funcName, 0x00, MAX_PATH);
						while(k!=MAX_PATH && readB(2+nameImg+k)!=0)
						{
							funcName[k]=readB(nameImg+2+k);
							k++;
						}
						funcAddr=readDw(simplesFt);

						if(!isForwardedFunction(funcName, dest))
						{
							if(funcAddr < dest->codeAddr || funcAddr > dest->endOfCodeAddr)
								fprintf(currentFile, "111|%d|%s||%s.%s|%s.0x%x\n", currentPid, mod->moduleFileName, name, funcName, whosthisaddr(funcAddr), funcAddr);
						}

						//Next !
						originalsFt+=4;
						simplesFt+=4;
						delete[] funcName;
						funcName=NULL;
					}
				}
				else
				{
					fprintf(currentFile, "112|%d|%s||%s|\n\n", currentPid, mod->moduleFileName, name);
				}

				delete[] name;
				name=NULL;
			}
		}
		i++;
	}
}