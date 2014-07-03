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

VOID findIdtHooks(PCHAR report, ULONG size, ULONG baseKrnl, ULONG endKrnl)
{
	//thx to 0vercl0k @ blog.nibbles.fr/26
	IDTINFO idtInfo;
	PIDTENTRY idtEntry;
	ULONG i, j, nbCPU, handler;
	USHORT mask;
	CHAR temp[256];
	// DbgPrint("findIdtHooks\n");
	mask = 1;
	nbCPU = KeNumberProcessors;
	
	for(i = 0; i < nbCPU; i++)
	{
		KeSetAffinityThread((ULONG)KeGetCurrentThread(), mask);
		__asm
		{
			sidt idtInfo
		}
		idtEntry = (PIDTENTRY)(idtInfo.HighIDTbase<<16 | idtInfo.LowIDTbase);
		//DbgPrint("#%i IDT : %x\n", i,idtEntry);
		for(j = 0; j < 0xFF; j++)
		{
			handler = (ULONG)(idtEntry[j].HighOffset << 16 | idtEntry[j].LowOffset);
			//DbgPrint("CPU #%i #%x handler = 0x%x ", i, j, handler);
			if((handler < baseKrnl || handler > endKrnl) && handler != 0)
			{
				//DbgPrint("CPU #%i #%x handler = 0x%x hook\n", i, j, handler);
				if(RtlStringCbPrintfA(temp, 256*sizeof(char), "270|r0|||#%i.%x IDT handler|%s.0x%x\n", i+1, j, whosThisAddr(handler), handler)==STATUS_SUCCESS)
				{
					if(RtlStringCchCatA(report, size, temp) != STATUS_SUCCESS)
					{
						DbgPrint("Error : RtlStringCchCat\n");
						return NULL;
					}
				}
				else
				{
					DbgPrint("Error : RtlStringCbVPrintf\n");
					return NULL;
				}
			}
		}
		mask <<=1;
	}

}
