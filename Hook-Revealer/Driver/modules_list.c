// Copyright 2013 Conix Security, Adrien Chevalier
// adrien.chevalier@conix.fr
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.
#include "rootkitdetect.h"
CHAR unknown[]="unknown\x00";

VOID listLoadedModules(PCHAR report, ULONG size, PULONG pulModuleList)
{
	NTSTATUS ret;
	PSYSTEM_MODULE_INFORMATION pMods;
	ULONG i;
	PSYSTEM_MODULE currentMod;
	CHAR temp[256];
	PCHAR shortName;
	
	// DbgPrint("listLoadedModules\n");
	pMods = (PSYSTEM_MODULE_INFORMATION) pulModuleList;
	
	for(i = 0; i<pMods->ModulesCount; i++)
	{
		currentMod=&pMods->Modules[i];
		shortName = (PCHAR)(currentMod->Name + currentMod->NameOffset);
		
		if(RtlStringCbPrintfA(temp, 256*sizeof(char), "240|r0||%s||0x%x\n", shortName, currentMod->ImageBaseAddress)==STATUS_SUCCESS)
		{
			if(RtlStringCchCatA(report, size, temp) != STATUS_SUCCESS)
			{
				DbgPrint("Error : RtlStringCchCat\n");
				return ;
			}
		}
		else
		{
			DbgPrint("Error : RtlStringCbVPrintf\n");
			return ;
		}
		
		//DbgPrint("%s : %x - %x\n", (PCHAR)(currentMod->Name + currentMod->NameOffset), currentMod->ImageBaseAddress, (currentMod->ImageBaseAddress + currentMod->ImageSize));
		module_analysis(report, size, (PCHAR)(currentMod->Name + currentMod->NameOffset), currentMod->ImageBaseAddress, (currentMod->ImageBaseAddress + currentMod->ImageSize));
	}
}

PCHAR whosThisAddr(ULONG funcAddr)
{
	PSYSTEM_MODULE currentMod;
	ULONG i;
	// DbgPrint("whosThisAddr(0x%x)\n", funcAddr);
	for(i = 0; i<modulesInMemory->ModulesCount; i++)
	{
		currentMod=&modulesInMemory->Modules[i];
		
		if(funcAddr > currentMod->ImageBaseAddress && funcAddr < currentMod->ImageBaseAddress+currentMod->ImageSize) //ok addr
		{
			if(currentMod->Name != NULL)
			{
				// DbgPrint("Identified : %s\n", (PCHAR)(currentMod->Name + currentMod->NameOffset));
				return (PCHAR)(currentMod->Name + currentMod->NameOffset);
			}
			else
				return unknown;
		}
	}
	
	// DbgPrint("%x not found in modules...\n",  funcAddr);
	return unknown;

}

ULONG isAddrIntoModule(ULONG funcAddr, PCHAR modName)
{
	PSYSTEM_MODULE currentMod;
	ULONG i;
	for(i = 0; i<modulesInMemory->ModulesCount; i++)
	{
		currentMod=&modulesInMemory->Modules[i];
		if(_stricmp(modName, (PCHAR)(currentMod->Name + currentMod->NameOffset))==0) //okay, module
		{
			if(funcAddr > currentMod->ImageBaseAddress && funcAddr < currentMod->ImageBaseAddress+currentMod->ImageSize) //ok addr
				return 1;
			else
				return 0; //argh, dis iz not good...
		}
	}
	
	//DbgPrint("%s.%x not found in modules...\n", modName, funcAddr);
	return 0;
}



