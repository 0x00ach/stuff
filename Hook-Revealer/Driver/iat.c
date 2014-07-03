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

VOID findIatHook(PCHAR report, ULONG size, PCHAR name, ULONG baseAddr, ULONG endAddr, ULONG iatAddr, ULONG iatSize)
{
	// DbgPrint("findIatHook\n");
	/*
	==================
	====== TODO ======
	==================
	
	ULONG currentEntry, originalsFt, simplesFt, nameImg, funcAddr, modNameOffset;
	ULONG i;
	ULONG nbOfEntries;
	PCHAR funcName, modName;
	CHAR temp[256];

	DbgPrint("======== Mod : %s ; IAT : 0x%x ; IAT size : 0x%x\n", name, iatAddr, iatSize);
	if(iatAddr == baseAddr)
	{
		//DbgPrint(" IAT addr not good...\n");
		return;
	}
	
	nbOfEntries = iatSize / sizeof(IMAGE_IMPORT_DESCRIPTOR) -1;
	DbgPrint("nbOfEntries : %x\n", nbOfEntries);
	
	if(nbOfEntries <= 0)
	{
		DbgPrint(" No IAT entries\n");
		return;
	}
	
	i = 0;
	modNameOffset = 1;
	while(modNameOffset != 0)
	{
		//IAT = IMAGE_IMPORT_DESCRIPTOR[nbOfEntries]
		currentEntry=iatAddr + (i*sizeof(IMAGE_IMPORT_DESCRIPTOR));
		
		DbgPrint("currentEntry : %x\n", currentEntry);
		
		//IMAGE_IMPORT_DESCRIPTOR.Name (+12)
		modNameOffset=*(PULONG)(currentEntry + 12);
		DbgPrint("modNameOffset : %x\n", modNameOffset);
		
		if(modNameOffset != 0)
		{
			modName=(PCHAR)(baseAddr+modNameOffset);
			DbgPrint("Mod import : %s\n", modName);
			/*
			//IMAGE_IMPORT_DESCRIPTOR.OriginalFirstThunk
			originalsFt=(*(PULONG)(currentEntry))+baseAddr;
			//IMAGE_IMPORT_DESCRIPTOR.FirstThunk
			simplesFt=(*(PULONG)((PUCHAR)currentEntry + 16))+baseAddr;
			
			DbgPrint("simplesFt = 0x%x\n", simplesFt);
			DbgPrint("originalsFt = 0x%x\n", originalsFt);
			
			while(*(PULONG)(originalsFt)!=0)
			{
				funcName = (PCHAR)(*(PULONG)originalsFt+baseAddr+2);
				DbgPrint("funcNameAddr : 0x%x\n", funcName);
				DbgPrint("Func import : %s", funcName);
				funcAddr=*(PULONG)(simplesFt);
				DbgPrint(" at 0x%x", funcAddr);

				if(isAddrIntoModule(modName, funcAddr) == 0)
				{
					DbgPrint(" HOOOK\n", funcAddr);
					if(RtlStringCbPrintfA(temp, 256*sizeof(char), "260|r0|||%s :: %s.%s|0x%x\n", name, modName, funcName, funcAddr)==STATUS_SUCCESS)
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
				}
				else
					DbgPrint(" SAFE\n", funcAddr);
				//Next !
				originalsFt+=4;
				simplesFt+=4;
			}
		}
		i++;
	}
	*/
}
