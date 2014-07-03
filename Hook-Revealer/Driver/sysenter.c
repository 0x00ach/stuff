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

// 
// Read the MSR register to identify hooks and reads first bytes to find inline
// hooks.
//
VOID findSYSENTERHook(PCHAR report, ULONG size, ULONG kernelBase, ULONG kernelEnd)
{
	ULONG ulFastCallLoc = 0;
	CHAR temp[256];
	UCHAR firstByte=0;
	ULONG cpt = 0;
	ULONG zwaddr = 0;
	ULONG kisysservreladdr = 0;
	ULONG kisysservaddr = 0;
	
// read MSR register
	__asm
	{
		mov ecx, 0x176
		rdmsr
		mov ulFastCallLoc, eax
	}
	
// find hook
	if(ulFastCallLoc<kernelBase || ulFastCallLoc>kernelEnd)
	{
		if(RtlStringCbPrintfA(temp, 256*sizeof(char), "220|r0|||MSR KiFastCallEntry address hijacked|%s.0x%x\n", whosThisAddr(ulFastCallLoc), ulFastCallLoc)==STATUS_SUCCESS)
		{
			if(RtlStringCchCatA(report, size, temp) != STATUS_SUCCESS)
				DbgPrint("Error : RtlStringCchCat\n");
		}
		else 
			DbgPrint("Error : RtlStringCbVPrintf\n");
	}
	else
	{
// find inline hook at KiFastCallEntry
		firstByte=*(PUCHAR)ulFastCallLoc;
		if(firstByte == 0xE9 || firstByte == 0xE8 || firstByte == 0xEB)
		{
			if(RtlStringCbPrintfA(temp, 256*sizeof(char), "220|r0|||KiFastCallEntry (0x%x) inline hooked|\n", ulFastCallLoc)==STATUS_SUCCESS)
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
	
// KiSystemService = ZwQuerySystemInformation + 12 : CALL KiSystemService
	kisysservreladdr=*(PULONG)(((PUCHAR)&ZwQuerySystemInformation)+13);
	
// ZwQuerySystemInformation
	zwaddr=(ULONG)&ZwQuerySystemInformation;
// KiSystemService
	kisysservaddr=zwaddr+kisysservreladdr+5;
	
// 
	if(kisysservaddr<kernelBase || kisysservaddr>kernelEnd)
	{
		if(RtlStringCbPrintfA(temp, 256*sizeof(char), "220|r0|||ZwQuerySystemInformation inline hooked (KiSystemService redir)|0x%x\n", kisysservaddr)==STATUS_SUCCESS)
		{
			if(RtlStringCchCatA(report, size, temp) != STATUS_SUCCESS)
				DbgPrint("Error : RtlStringCchCat\n");
		}
		else 
			DbgPrint("Error : RtlStringCbVPrintf\n");
	}
	else
	{
		findInlineHooks(report, size, "ntoskrnl", "KiSystemService", kisysservaddr, kernelBase, kernelEnd);
	}
}
