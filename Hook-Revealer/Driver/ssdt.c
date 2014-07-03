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

VOID findSSDTHooks(PCHAR report, ULONG size, ULONG kernelBase, ULONG kernelEnd)
{
	PULONG pulModuleList = NULL;
	CHAR temp[256];
	ULONG nbEntries = 0;
	ULONG cpt = 0;
	// DbgPrint("findSSDTHooks\n");
	pulModuleList = modulesInMemory;
	
	//récupération de l'@ de la SSDT
	nbEntries=KeServiceDescriptorTable.NumberOfServices;
	//pour chaque entrée de la SSDT
	for(cpt=0; cpt<nbEntries; cpt++)
	{
		//si hors limites
		if(KeServiceDescriptorTable.ServiceTableBase[cpt] < kernelBase || KeServiceDescriptorTable.ServiceTableBase[cpt] > kernelEnd)
		{
			if(RtlStringCbPrintfA(temp, 256*sizeof(char), "210|r0|||#%x syscall|%s.0x%x\n", cpt, whosThisAddr(KeServiceDescriptorTable.ServiceTableBase[cpt]), KeServiceDescriptorTable.ServiceTableBase[cpt])==STATUS_SUCCESS)
			{
				//DbgPrint("HOOK : #0x%x -> 0x%x\n", cpt, KeServiceDescriptorTable.ServiceTableBase[cpt]);
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
	}
}
