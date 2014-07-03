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

VOID module_analysis(PCHAR report, ULONG size, PCHAR modName, ULONG baseAddr, ULONG endAddr)
{

	ULONG eatAddr;
	ULONG iatAddr;
	ULONG peOffset;
	ULONG peAddr;
	ULONG iatSize;
	
	// DbgPrint("module_analysis : %s\n",modName);
	if(*((PUSHORT)baseAddr)!=0x5A4D)
	{
		//DbgPrint(" %s is not a PE file\n", modName);
		return;
	}
	peOffset = *(PULONG)(baseAddr + 0x3C);
	if(peOffset == 0)
	{
		//DbgPrint(" %s is not a PE file\n", modName);
		return;
	}
	peAddr = (baseAddr + peOffset);
	
	eatAddr = *(PULONG)(peAddr + 0x78); // eat -> parsing -> Inline hooks
	
	if(eatAddr!=0)
	{
		eatAddr = eatAddr + baseAddr;
		eatParsing(report, size, modName, baseAddr, endAddr, eatAddr);
	}
	
	
	// TODO
	// IAT / EAT
	// iatAddr = *(PULONG)(peAddr + 0x80); // iat -> parsing -> IAT hooks
	// iatSize = *(PULONG)(peAddr + 0x84); 
	// if(iatAddr != 0 && iatSize != 0)
	// {
		// iatAddr = iatAddr + baseAddr;
		// findIatHook(report, size, modName, baseAddr, endAddr, iatAddr, iatSize);
	// }

}
