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

VOID eatParsing(PCHAR report, ULONG size, PCHAR modName, ULONG baseAddr, ULONG endAddr, ULONG eatAddr)
{
	ULONG npt, fpt, opt;
	ULONG numberOfNames, funcAddr;
	PCHAR name;
	USHORT currentOrdinal;
	ULONG i;
	
	if(eatAddr == baseAddr)
		return;
	
	//parsing EAT (address of names, functions & ordinals)
	npt = *(PULONG)(eatAddr + 0x20)+baseAddr;
	fpt = *(PULONG)(eatAddr + 0x1C)+baseAddr;
	opt = *(PULONG)(eatAddr + 0x24)+baseAddr;
	
	numberOfNames = *(PULONG)(eatAddr + 0x18);
	
	for(i=0; i<numberOfNames; i++)
	{
		name = (PCHAR)(*(PULONG)(npt + (i*4))+baseAddr);
		currentOrdinal = *(PUSHORT)(opt + (i*2));
		funcAddr = *(PULONG)(fpt + (currentOrdinal*4));
		if(funcAddr != 0)
		{
			funcAddr = funcAddr + baseAddr;
			findInlineHooks(report, size, modName, name, funcAddr, baseAddr, endAddr);
		}
	}
}

