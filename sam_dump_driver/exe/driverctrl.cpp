#include "samdump.h"
SC_HANDLE manager;
SC_HANDLE service;
//retourne le status du driver
int driverStatus()
{
	DWORD dwBytes;
	SERVICE_STATUS_PROCESS status;

	if(!manager)
		manager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if(!manager)
		return 0;
	
	if(!service)
		service=OpenServiceA( manager, "conixsamdump",  SERVICE_ALL_ACCESS);
	if(!service)
		return DRIVER_NOT_INSTALLED;
	
	if(!QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO, (LPBYTE)&status, sizeof(SERVICE_STATUS_PROCESS), &dwBytes))
		return 0;

	if(status.dwCurrentState == SERVICE_STOPPED || status.dwCurrentState == SERVICE_STOP_PENDING)
		return DRIVER_STOPPED;

	return DRIVER_STARTED;
}


//installation du driver ./conixsamdump.sys
bool install_driver()
{
	char* currentPath=new char[1024];
	char* fullDriverPath=NULL;

	if(!manager)
		manager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if(!manager)
		return false;

	
	GetCurrentDirectoryA(1024, currentPath);
	std::string temp=std::string(currentPath)+"\\samdump.sys";
	delete currentPath;
	fullDriverPath=(char*)temp.c_str();

	service = CreateServiceA(manager,"conixsamdump","conixsamdump",SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START,SERVICE_ERROR_NORMAL,fullDriverPath,NULL,NULL,NULL,NULL,NULL);
	if(!service)
		return false;
	//printf("[+] Driver installed\n");
	return true;
}


//suppression du driver (apres stop)
bool remove_driver()
{
	if(!manager)
		manager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if(!manager)
		return false;

	if(!service)
		service=OpenServiceA( manager, "conixsamdump",  SERVICE_ALL_ACCESS);
	if(!service)
		return false;
	
    if (! DeleteService(service) )
        return false;
    
	return true;
}


bool start_service()
{
	if(!manager)
		manager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);

	if(!manager)
		return false;
	
	if(!service)
		service = OpenServiceA( manager, "conixsamdump",  SERVICE_ALL_ACCESS);
	if (!service)
		return false;

	if(!StartServiceA(service, 0, NULL))
		return false;

	return true;
}

//stop du service
bool stop_service()
{
	SERVICE_STATUS useless;

	if(!manager)
		manager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if(!manager)
		return false;

	if(!service)
		service = OpenServiceA( manager, "conixsamdump",   SERVICE_STOP);

	if(!service)
		return false;
	
	if(!ControlService(service, SERVICE_CONTROL_STOP, &useless))
		return false;

	return true;
}

// fermeture des handle du driver
void sCCleanHandles()
{
	if(manager)
		CloseServiceHandle(manager);
	if(service)
		CloseServiceHandle(service);
}