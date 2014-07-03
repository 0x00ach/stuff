#include "hook_revealer.h"


void analysis::detect_inline_hook(pmodule mod, char* name, DWORD funcAddr)
{
	BYTE first = readB(funcAddr);
	BYTE second = readB(funcAddr+1);
	BYTE sixth = readB(funcAddr+5);
	BYTE seventh = readB(funcAddr+6);
	DWORD lowLimit = mod->codeAddr;
	DWORD highLimit = mod->endOfCodeAddr;
	char* targetModName=NULL;
	DWORD destAddr = 0;

	if(first == 0xEB && second==0xF9)
	{
		//E9 0xDEADBEEF : hook vers Adresse+5+0xDEADBEEF
		//EBF9 : JMP SHORT -5
		destAddr=readDw(funcAddr-4);
		destAddr=destAddr+(funcAddr);
		targetModName=whosthisaddr(destAddr);
		fprintf(currentFile, "135|%d|%s||%s (0x%x)|%s.0x%x\n", currentPid, mod->moduleFileName, name, funcAddr, targetModName, destAddr);
	}
	if(first == 0xE8)
	{
		//E8 0xDEADBEEF : hook vers Adresse+5+0xDEADBEEF
		destAddr=readDw(funcAddr+1);
		destAddr=destAddr+(funcAddr+5);
		targetModName=whosthisaddr(destAddr);
		if(destAddr < lowLimit || destAddr > highLimit)
			fprintf(currentFile, "133|%d|%s||%s (0x%x)|%s.0x%x\n", currentPid, mod->moduleFileName, name, funcAddr, targetModName, destAddr);
	}
	if(first == 0xE9)
	{
		//E9 0xDEADBEEF : hook vers Adresse+5+0xDEADBEEF
		destAddr=readDw(funcAddr+1);
		destAddr=destAddr+(funcAddr+5);
		targetModName=whosthisaddr(destAddr);
		if(destAddr < lowLimit || destAddr > highLimit)
			fprintf(currentFile, "131|%d|%s||%s (0x%x)|%s.0x%x\n", currentPid, mod->moduleFileName, name, funcAddr, targetModName, destAddr);
	}
	if(first == 0x0F && second==0x84)
	{
		//0F84 0xDEADBEEF : hook vers Adresse+6+0xDEADBEEF car en début de fonction, le JE sera pris
		destAddr=readDw(funcAddr+2);
		destAddr=destAddr+(funcAddr+6);
		targetModName=whosthisaddr(destAddr);
		if(destAddr < lowLimit || destAddr > highLimit)
			fprintf(currentFile, "132|%d|%s||%s (0x%x)|%s.0x%x\n", currentPid, mod->moduleFileName, name, funcAddr, targetModName, destAddr);
	}
	if( first == 0xC8 && ( sixth==0xC3 || sixth==0xC2 || ( sixth==0x90 && (seventh==0xC3 || seventh==0xC2 ))))
	{
		//C8 0xDEADBEEF : PUSH 0xDEADBEEF
		//NOP ?
		//C3/C2 0xABCD : RET ou RET 0xABCD
		destAddr=readDw(funcAddr+1);
		targetModName=whosthisaddr(destAddr);
		if(destAddr < lowLimit || destAddr > highLimit)
			fprintf(currentFile, "134|%d|%s||%s (0x%x)|%s.0x%x\n", currentPid, mod->moduleFileName, name, funcAddr, targetModName, destAddr);
	}


}