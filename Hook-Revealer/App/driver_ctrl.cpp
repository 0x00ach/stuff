#include "hook_revealer.h"


//lancement de l'analyse ring 0
void analysis::ring0analysis()
{
	manager=NULL;
	service=NULL;
	int error=0;
	int status = 0;

	status= driverStatus();
	
	if(status==0)
	{
		printf(" [-] Impossible to query the driver status.\n");
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
		ssdt();
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

int analysis::driverStatus()
{
	DWORD dwBytes;
	SERVICE_STATUS_PROCESS status;

	if(!manager)
		manager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if(!manager)
		return 0;
	
	if(!service)
		service=OpenServiceA( manager, "hookrevealer",  SERVICE_ALL_ACCESS);
	if(!service)
		return DRIVER_NOT_INSTALLED;
	
	if(!QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO, (LPBYTE)&status, sizeof(SERVICE_STATUS_PROCESS), &dwBytes))
		return 0;

	if(status.dwCurrentState == SERVICE_STOPPED || status.dwCurrentState == SERVICE_STOP_PENDING)
		return DRIVER_STOPPED;

	return DRIVER_STARTED;
}

bool analysis::ssdt()
{
	//buffer pour l'envoi
	BYTE buffer[0x10000];
	DWORD nbBytes=0;
	//buffer pour le retour
	char bufferRet[0x10000];
	HANDLE hDevice=NULL;

	//set
	memset(bufferRet, 0x00, 0x10000);

	 //you simply need to open the DOS Device Name using \\.\<DosName>.
    hDevice = CreateFileA("\\\\.\\hookrevealer",GENERIC_WRITE|GENERIC_READ,0,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
	if(hDevice == NULL)
	{
		printf(" [-] Impossible to open an handle on the driver.\n");
		return false;
	}

	if(!DeviceIoControl(hDevice,(DWORD)IOCTL_DETECT_HOOK,buffer,0x10000,bufferRet,0x10000,&nbBytes,NULL))
	{ 
		printf(" [-] Impossible to start ring0 analysis.\n");
		return false;
	}
	
	// écriture du rapport renvoyé, dans le fichier
	fprintf(currentFile, "%s\n", bufferRet);

	CloseHandle(hDevice);
	return true;
}	

//installation du driver ./rkdetect.sys
bool analysis::install_driver()
{
	char* currentPath=new char[1024];
	char* fullDriverPath=NULL;

	if(!manager)
		manager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if(!manager)
		return false;

	
	GetCurrentDirectoryA(1024, currentPath);
	std::string temp=std::string(currentPath)+"\\hookrevealer.sys";
	delete currentPath;
	fullDriverPath=(char*)temp.c_str();

	service = CreateServiceA(manager,"hookrevealer","hookrevealer",SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START,SERVICE_ERROR_NORMAL,fullDriverPath,NULL,NULL,NULL,NULL,NULL);
	if(!service)
		return false;

	return true;
}

//suppression du driver (apres stop)
bool analysis::remove_driver()
{
	if(!manager)
		manager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if(!manager)
		return false;

	if(!service)
		service=OpenServiceA( manager, "hookrevealer",  SERVICE_ALL_ACCESS);
	if(!service)
		return false;
	
    if (! DeleteService(service) )
        return false;
    
	return true;
}


bool analysis::start_service()
{
	if(!manager)
		manager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);

	if(!manager)
		return false;
	
	if(!service)
		service = OpenServiceA( manager, "hookrevealer",  SERVICE_ALL_ACCESS);
	if (!service)
		return false;

	if(!StartServiceA(service, 0, NULL))
		return false;

	return true;
}

//stop du service
bool analysis::stop_service()
{
	SERVICE_STATUS useless;

	if(!manager)
		manager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if(!manager)
		return false;

	if(!service)
		service = OpenServiceA( manager, "hookrevealer",   SERVICE_STOP);

	if(!service)
		return false;
	
	if(!ControlService(service, SERVICE_CONTROL_STOP, &useless))
		return false;

	return true;
}

// fermeture des handle du driver
void analysis::sCCleanHandles()
{
	if(manager)
		CloseServiceHandle(manager);
	if(service)
		CloseServiceHandle(service);
}