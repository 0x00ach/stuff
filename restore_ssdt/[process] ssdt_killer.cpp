#include <windows.h>
#include <psapi.h>
#include <stdio.h>
#include <iostream>
#include <fstream>
#include <string>
#include <tlhelp32.h>
#define SIOCTL_TYPE 40000
#define IOCTL_UNHOOK\
    CTL_CODE( SIOCTL_TYPE, 0x903, METHOD_BUFFERED, FILE_READ_DATA|FILE_WRITE_DATA)


bool elevate()
{
	TOKEN_PRIVILEGES priv;
	HANDLE n1;
	LUID luid;
	if(!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY, &n1))
	{
		printf(" [-] Error: SE_DEBUG access rights needed.\n");
		return false;
	}
	LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid);
	priv.PrivilegeCount=1;
	priv.Privileges[0].Luid=luid;
	priv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	if(!AdjustTokenPrivileges(n1, FALSE, &priv, sizeof(priv), NULL, NULL))
	{
		printf(" [-] Error: SE_DEBUG access rights needed.\n");
		return false;
	}
	CloseHandle(n1);

	if(!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY, &n1))
	{
		printf(" [-] Error: SE_LOAD_DRIVER access rights needed.\n");
		return false;
	}
	LookupPrivilegeValue(NULL, SE_LOAD_DRIVER_NAME, &luid);
	priv.PrivilegeCount=1;
	priv.Privileges[0].Luid=luid;
	priv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	if(!AdjustTokenPrivileges(n1, FALSE, &priv, sizeof(priv), NULL, NULL))
	{
		printf(" [-] Error: SE_LOAD_DRIVER access rights needed.\n");
		return false;
	}
	CloseHandle(n1);

	return true;
}


bool loadDriver()
{
	SC_HANDLE manager, service;
	char* currentPath=new char[1024];
	char* fullDriverPath;
	DWORD dwBytes;
	SERVICE_STATUS_PROCESS status;
	std::string temp;

	manager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if(!manager)
	{
		printf(" [-] Error: could not open service manager.\n");
		return false;
	}
	service=OpenServiceA( manager, "ssdtrestore",  SERVICE_ALL_ACCESS);
	if(!service)
	{
		GetCurrentDirectoryA(1024, currentPath);
		temp=std::string(currentPath)+"\\ssdtrestore.sys";
		delete currentPath;
		fullDriverPath=(char*)temp.c_str();

		service = CreateServiceA(manager,"ssdtrestore","ssdtrestore",SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START,SERVICE_ERROR_NORMAL,fullDriverPath,NULL,NULL,NULL,NULL,NULL);
		
		if(!service)
		{
			CloseServiceHandle(manager);
			printf(" [-] Error: could not install the service.\n");
			return false;
		}
		
		//start
		if(!StartServiceA(service, 0, NULL))
		{
			CloseServiceHandle(service);
			CloseServiceHandle(manager);
			printf(" [-] Error: could not start the service.\n");
			return false;
		}
	}
	else
	{
		//service registered. Is it started ?
		if(!QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO, (LPBYTE)&status, sizeof(SERVICE_STATUS_PROCESS), &dwBytes))
		{
			CloseServiceHandle(manager);
			CloseServiceHandle(service);
			printf(" [-] Error: could not query the service's status.\n");
			return false;
		}
		//no, well, let's start it
		if(status.dwCurrentState == SERVICE_STOPPED || status.dwCurrentState == SERVICE_STOP_PENDING)
		{
			if(!StartServiceA(service, 0, NULL))
			{
				CloseServiceHandle(service);
				CloseServiceHandle(manager);
				printf(" [-] Error: could not start the service.\n");
				return false;
			}
		}
	}

	
	CloseServiceHandle(service);
	CloseServiceHandle(manager);
	return true;
}
bool unloadDriver()
{
	SERVICE_STATUS useless;
	SC_HANDLE manager, service;

	manager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if(!manager)
	{
		printf(" [-] Error: could not open the service manager. Service not uninstalled.\n");
		return false;
	}

	service = OpenServiceA( manager, "ssdtrestore",   SERVICE_ALL_ACCESS);
	if(!service)
	{
		printf(" [-] Error: could not open the service. Service not uninstalled.\n");
		CloseServiceHandle(manager);
		return false;
	}

	if(!ControlService(service, SERVICE_CONTROL_STOP, &useless))
	{
		printf(" [-] Error: could not stop the service.\n");
	}

	if(!DeleteService(service))
	{
		printf(" [-] Error: could not uninstall the service.\n");
		CloseServiceHandle(service);
		CloseServiceHandle(manager);
		return false;
	}

	CloseServiceHandle(service);
	CloseServiceHandle(manager);
	return true;
}

void killprocesses()
{
	PROCESSENTRY32 procinfo;
	HANDLE hProc=CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);
	std::string processes[512];
	std::ifstream iss;
	int cpt=0;
	int c=0;
	
	printf("[+] Killing processes.\n");
	printf(" [-] Loading configuration.\n");
	iss.open("processes.txt", std::ios::in);
	if(!iss)
	{
		printf(" [-] Error: processes.txt file not found.\n");
		return;
	}

	if(!hProc)
	{
		printf(" [-] Error: impossible to enumerate processes.\n");
		return;
	}
	
	while(std::getline(iss, processes[cpt]) && cpt < 510)
		cpt++;

	procinfo.dwSize=sizeof(PROCESSENTRY32);

	if(!Process32First(hProc, &procinfo))
	{
		printf(" [-] Error: impossible to enumerate processes.\n");
		return;
	}

	while(Process32Next(hProc, &procinfo))
	{
		c=0;
		while(c<cpt)
		{
			if(!_stricmp(procinfo.szExeFile, processes[c].c_str()))
			{
				if(!TerminateProcess(OpenProcess(PROCESS_ALL_ACCESS, FALSE, procinfo.th32ProcessID), 0))
					printf(" [-] Could not kill %s (%d)\n", procinfo.szExeFile, procinfo.th32ProcessID);
				else
					printf(" [-] %s (%d) killed.\n", procinfo.szExeFile, procinfo.th32ProcessID);
				c=cpt; //break
			}
			c++;
		}
	}
}


void unloadDrivers()
{
	SERVICE_STATUS useless;
	SC_HANDLE manager, service;
	std::string driverz[512];
	std::ifstream iss;
	int cpt=0;
	int c=0;

	manager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);

	printf("[+] Unloading drivers.\n");
	

	printf(" [-] Loading configuration.\n");
	iss.open("drivers.txt", std::ios::in);
	if(!iss)
	{
		printf(" [-] Error: drivers.txt file not found.\n");
		return;
	}

	while(std::getline(iss, driverz[cpt]) && cpt < 510)
		cpt++;

	if(!manager)
	{
		printf(" [-] Error: could not open service manager.\n");
		return;
	}

	for(c=0; c<cpt; c++)
	{
		service = OpenServiceA( manager, driverz[c].c_str(),   SERVICE_ALL_ACCESS);
		if(service)
		{
			ControlService(service, SERVICE_CONTROL_STOP, &useless);
			if(DeleteService(service))
				printf(" [-] %s removed.\n", driverz[c].c_str());
			else
				printf(" [-] %s could not be removed.\n", driverz[c].c_str());
			CloseServiceHandle(service);
		}
	}

	CloseServiceHandle(manager);
}

void main()
{
	DWORD nbBytes;
	HANDLE hDevice;
	char bufferRet[6144];

	printf("[+] Elevating access rights.\n");
	if(!elevate())
	{
		system("pause");
		return;
	}

	printf("[+] Loading driver.\n");
	if(!loadDriver())
	{
		printf(" [-] Error: the driver has not been installed.\n");
		system("pause");
		return;	
	}

	memset(bufferRet, 0x00, 6144);

	printf("[+] Restoring KiSystemService table.\n");

	 //you simply need to open the DOS Device Name using \\.\<DosName>.
    hDevice = CreateFileA("\\\\.\\ssdtrestore",GENERIC_WRITE|GENERIC_READ,0,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
	if(hDevice == NULL)
		printf(" [-] Error: Could not communicate with the service.\n");
	else
		if(!DeviceIoControl(hDevice,IOCTL_UNHOOK,"lulz",4,bufferRet,6144,&nbBytes,NULL))
			printf(" [-] Error: Could not communicate.\n");

	killprocesses();
	unloadDrivers();

	if(unloadDriver())
		printf("[+] Driver unloaded.\n");

	system("pause");
}
