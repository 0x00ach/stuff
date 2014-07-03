#include "samdump.h"

void main(int argc, char** argv)
{	
	if(argc == 1)
	{
		printf("\n\t\tSAM DUMP -- CONIX SECURITY\n\n");
		printf("Utilisation : %s -[h|s|v|a]\n", argv[0]);
		printf("Entrer \"%s -h\" pour plus d'informations.\n", argv[0]);
	}
	else
	{
		if(!_stricmp(argv[1], "-h"))
		{
			printf("\n\t\tSAM DUMP -- CONIX SECURITY\n\n");
			printf("Ce programme permet de recuperer les empreintes des mots de passe\n");
			printf("des comptes locaux du systeme.\n");
			printf("Options :\n");
			printf("\t[+] -h : affiche ce message\n");
			printf("\t[+] -s : cree le fichier \"S\" contenant la SYSKEY\n");
			printf("\t[+] -v : cree les fichiers \"0000XXXX\" contenant les empreintes\n");
			printf("\tdes mots de passe. Necessite la presence du driver \"samdump.sys\".\n");
			printf("\tCree egalement le fichier \"F\".\n");
			printf("\tNe fonctionne que sur des systemes 32 bits.\n");
			printf("\t[+] -a : -s -v en meme temps\n");
		}
		if(!_stricmp(argv[1], "-s"))
			dumpSyskey();
		if(!_stricmp(argv[1], "-v"))
			dumpHashes();
		if(!_stricmp(argv[1], "-a"))
		{
			dumpSyskey();
			dumpHashes();
		}
	}
	return;
}
