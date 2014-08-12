#include "main.h"

ULONG original_int3_handler;
ULONG original_int6_handler;

VOID restoreIDT()
{
	IDTR idtptr;
	PIDT_DESCRIPTOR idtEntry;
	
	ULONG i, j, nbCPU, handler;
	ULONG entryAddr;
	USHORT mask;
	CHAR temp[256];
	
	DbgPrint("- IDT - restoreIDT()\n");
	
	mask = 1;
	nbCPU = KeNumberProcessors;
	
	for(i = 0; i < nbCPU; i++)
	{
		KeSetAffinityThread((PKTHREAD)KeGetCurrentThread(), mask);
		
		__asm
		{
			cli
			sidt idtptr
			sti
		}
		idtEntry = (PIDT_DESCRIPTOR)(idtptr.HighIDTbase<<16 | idtptr.LowIDTbase);
		
		entryAddr = (ULONG)&(idtEntry[3]);
		__asm
		{
			cli
			mov eax, original_int3_handler
			mov ebx, entryAddr
			mov [ebx], ax
			shr eax, 16
			mov [ebx+6],ax
			lidt idtptr
			sti
		}
		entryAddr = (ULONG)&(idtEntry[6]);
		__asm
		{
			cli
			mov eax, original_int6_handler
			mov ebx, entryAddr
			mov [ebx], ax
			shr eax, 16
			mov [ebx+6],ax
			lidt idtptr
			sti
		}
		
		
		mask <<=1;
	}
}

VOID hookIDT()
{
	IDTR idtptr;
	PIDT_DESCRIPTOR idtEntry;
	
	ULONG i, j, nbCPU;
	ULONG entryAddr;
	USHORT mask;
	CHAR temp[256];
	
	DbgPrint("- IDT - hookIDT()\n");
	
	mask = 1;
	nbCPU = KeNumberProcessors;
	
	for(i = 0; i < nbCPU; i++)
	{
		KeSetAffinityThread((PKTHREAD)KeGetCurrentThread(), mask);
		__asm
		{
			cli
			sidt idtptr
			sti
		}
		idtEntry = (PIDT_DESCRIPTOR)(idtptr.HighIDTbase<<16 | idtptr.LowIDTbase);
		DbgPrint("- IDT - #%i IDT : %x\n", i,idtEntry);
		
		original_int3_handler = (ULONG)((idtEntry[3].HighOffset << 16) | idtEntry[3].LowOffset);
		DbgPrint("- IDT - CPU #%i original #INT3 handler = 0x%x ", i, original_int3_handler);
		
		entryAddr = (ULONG)&(idtEntry[3]);
		__asm
		{
			cli
			lea eax, int3Handler
			mov ebx, entryAddr
			mov [ebx], ax
			shr eax, 16
			mov [ebx+6],ax
			lidt idtptr
			sti
		}
		original_int6_handler = (ULONG)((idtEntry[6].HighOffset << 16) | idtEntry[6].LowOffset);
		DbgPrint("- IDT - CPU #%i original #INT3 handler = 0x%x ", i, original_int6_handler);
		entryAddr = (ULONG)&(idtEntry[6]);
		__asm
		{
			cli
			lea eax, int6Handler
			mov ebx, entryAddr
			mov [ebx], ax
			shr eax, 16
			mov [ebx+6],ax
			lidt idtptr
			sti
		}
		
		mask <<=1;
	}

}



_declspec(naked) int3Handler()
{
    __asm    
    {
        pushfd
        pushad
		push fs
		mov bx, 0x30
		mov fs, bx
		
		
        mov ebx,esp
        add ebx,40
        push ebx
        call int3Check
        cmp eax,0
        je fin3

		pop fs
        popad
        popfd
        iretd

        fin3:
		pop fs
		popad
        popfd
        jmp original_int3_handler
    }
}

_declspec(naked) int6Handler()
{
    __asm    
    {
        pushfd
        pushad
		push fs
		mov bx, 0x30
		mov fs, bx
		
        mov ebx,esp
        add ebx,40
        push ebx
        call int6Check
        cmp eax,0
        je fin6
		
		pop fs
        popad
        popfd
        iretd

        fin6:
		pop fs
		popad
		popfd
		jmp original_int6_handler
    }
}

ULONG __stdcall int3Check(PINTTERUPT_STACK savedstack)
{
	DbgPrint("INT 3 - IRQL %x -- RETURN ADDR %.8x -- TID %x\n",KeGetCurrentIrql(), savedstack->InterruptReturnAddress, PsGetCurrentThreadId());
	
	return 0;
}
//http://www.codeproject.com/Articles/13677/Hooking-the-kernel-directly
ULONG __stdcall int6Check(PINTTERUPT_STACK savedstack)
{
	DbgPrint("INT 6 - IRQL %x -- RETURN ADDR %.8x -- TID %x\n",KeGetCurrentIrql(), savedstack->InterruptReturnAddress, PsGetCurrentThreadId());
	savedstack->InterruptReturnAddress = savedstack->InterruptReturnAddress+4;
	//savedstack->SavedFlags &=0xfffffeff;
	return 1;
}