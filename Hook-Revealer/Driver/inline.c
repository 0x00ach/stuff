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

VOID findInlineHooks(PCHAR report, ULONG size, PCHAR modName, PCHAR funcName, ULONG funcAddr, ULONG base, ULONG end)
{
	UCHAR first, second, sixth, seventh;
	ULONG dest;
	USHORT dest2;
	CHAR temp[256];
	// DbgPrint("findInlineHook\n");
	first = *(PUCHAR)funcAddr;
	second = *((PUCHAR)funcAddr+1);
	sixth = *((PUCHAR)funcAddr+5);
	seventh = *((PUCHAR)funcAddr+6);
	dest = 0;
	
	// test
	//DbgPrint(" %s.%s : 0x%x 1st, 2nd, 6th and 7th bytes : %x %x %x %x\n", modName, funcName, funcAddr, first, second, sixth, seventh);
	if(first == 0xEB && second==0xF9)
	{
		dest = *(PULONG)((PUCHAR)funcAddr - 4); //Hot patch : JMP SHORT - 5 -> JMP / CALL
		dest = dest + funcAddr;
		if(dest < base || dest > end)
		{
			//DbgPrint("Hook : %s.%s.0x%x ::: 0x%x :: bytes = %x", modName, funcName, funcAddr, dest);
			if(RtlStringCbPrintfA(temp, 256*sizeof(char), "230|r0|%s||%s (0x%x)|%s.0x%x (HOTPATCH)\n", modName, funcName, funcAddr, whosThisAddr(dest), dest)==STATUS_SUCCESS)
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
	}
	if(first == 0xE8)
	{
		dest = *(PULONG)((PUCHAR)funcAddr + 1); //CALL
		dest = dest + funcAddr + 5;
		if(dest < base || dest > end)
		{
			//DbgPrint("Hook : %s.%s.0x%x ::: 0x%x", modName, funcName, funcAddr, dest);
			if(RtlStringCbPrintfA(temp, 256*sizeof(char), "230|r0|%s||%s (0x%x)|%s.0x%x (CALL)\n", modName, funcName, funcAddr, whosThisAddr(dest), dest)==STATUS_SUCCESS)
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
	}
	if(first == 0xE8)
	{
		dest = *(PULONG)((PUCHAR)funcAddr + 1); //JMP
		dest = dest + funcAddr + 5;
		if(dest < base || dest > end)
		{
			//DbgPrint("Hook : %s.%s.0x%x ::: 0x%x", modName, funcName, funcAddr, dest);
			if(RtlStringCbPrintfA(temp, 256*sizeof(char), "230|r0|%s||%s (0x%x)|%s.0x%x (JMP)\n", modName, funcName, funcAddr, whosThisAddr(dest), dest)==STATUS_SUCCESS)
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
	}
	if( first == 0xC8 && ( sixth==0xC3 || sixth==0xC2 || ( sixth==0x90 && (seventh==0xC3 || seventh==0xC2 ))))
	{
		dest = *((PULONG)(PUCHAR)funcAddr +1); //PUSH RET
		dest = dest + funcAddr;
		if(dest < base || dest > end)
		{
			//DbgPrint("Hook : %s.%s.0x%x ::: 0x%x", modName, funcName, funcAddr, dest);
			if(RtlStringCbPrintfA(temp, 256*sizeof(char), "230|r0|%s||%s (0x%x)|%s.0x%x (PUSH/RET)\n", modName, funcName, funcAddr, whosThisAddr(dest), dest)==STATUS_SUCCESS)
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
	}
	if(first == 0x0F && second==0x84)
	{
		dest = *(PULONG)((PUCHAR)funcAddr + 1); //JE
		dest=dest+(funcAddr+6);
		if(dest < base || dest > end)
		{
			//DbgPrint("Hook : %s.%s.0x%x ::: 0x%x", modName, funcName, funcAddr, dest);
			if(RtlStringCbPrintfA(temp, 256*sizeof(char), "230|r0|%s||%s (0x%x)|%s.0x%x (JE JMP)\n", modName, funcName, funcAddr, whosThisAddr(dest), dest)==STATUS_SUCCESS)
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
	}
	if(first == 0xEA)
	{
		dest = *(PULONG)((PUCHAR)funcAddr +1);  // FAR JMP
		dest = dest + funcAddr;
		dest2 = *((PUCHAR)funcAddr + 5);
		if(dest < base || dest > end)
		{
			//DbgPrint("Hook : %s.%s.0x%x ::: 0x%x ::: BYTES : 0x%x", modName, funcName, funcAddr, dest, *(PULONG)(funcAddr));
			if(RtlStringCbPrintfA(temp, 256*sizeof(char), "230|r0|%s||%s (0x%x)|%s.%x:%x (FAR JMP)\n", modName, funcName, funcAddr, whosThisAddr(dest2), dest2, dest)==STATUS_SUCCESS)
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
	}
}
