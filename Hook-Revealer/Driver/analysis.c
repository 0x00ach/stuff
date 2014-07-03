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

VOID startAnalysis(PCHAR report, PCHAR size)
{
	ULONG ulNeededSize = 0;
	PULONG pulModuleList = NULL;
	PSYSTEM_MODULE pKernelInfo = NULL;
	ULONG kernelBase = 0;
	ULONG kernelEnd = 0;
	NTSTATUS ret = 0;
	
	//taille nécessaire pour la structure ?
	ZwQuerySystemInformation(11, &ulNeededSize, 0, &ulNeededSize);
	if(ulNeededSize == 0)
	{
		DbgPrint("ZwQuerySystemInformation failed.\n");
		return NULL;
	}
	pulModuleList = ExAllocatePoolWithTag(PagedPool, ulNeededSize, 'tdkr');
	
	ret = ZwQuerySystemInformation(11, pulModuleList, ulNeededSize, 0); 
	if(ret != STATUS_SUCCESS)
	{
		DbgPrint("ZwQuerySystemInformation failed.\n");
		if(pulModuleList!=NULL)
			ExFreePool(pulModuleList);
		return ;
	}
	
	//récupération de la plage mémoire du kernel
	modulesInMemory=(PSYSTEM_MODULE_INFORMATION) pulModuleList;
	
	//1st module : ntoskrnl
	pKernelInfo=&modulesInMemory->Modules[0];
	kernelBase=(ULONG)pKernelInfo->ImageBaseAddress;
	kernelEnd=kernelBase+pKernelInfo->ImageSize;
	
	
	/************************************
	
		START ANALYSIS
	
	*************************************/
	//Listing / Inline / IAT
	listLoadedModules( report,  size,  pulModuleList);
	//SYSENTER
	findSYSENTERHook(report, size, kernelBase, kernelEnd);
	//SSDT
	findSSDTHooks(report, size, kernelBase, kernelEnd);
	//IRP
	findIrpHooks(L"\\Driver", report, size);
	//IDT
	findIdtHooks(report, size, kernelBase, kernelEnd);

	if(pulModuleList!=NULL)
		ExFreePool(pulModuleList);
}
