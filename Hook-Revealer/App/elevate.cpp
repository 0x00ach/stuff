#include "hook_revealer.h"


bool elevate_driver()
{
	TOKEN_PRIVILEGES priv;
	HANDLE n1;
	LUID luid;

	if(!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY, &n1))
	{
		printf(" [+] Impossible d'obtenir les droits SE_LOAD_DRIVER.\n");
		return false;
	}

	LookupPrivilegeValue(NULL, SE_LOAD_DRIVER_NAME, &luid);
	priv.PrivilegeCount=1;
	priv.Privileges[0].Luid=luid;
	priv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	if(!AdjustTokenPrivileges(n1, FALSE, &priv, sizeof(priv), NULL, NULL))
	{
		printf(" [+] Impossible d'obtenir les droits SE_LOAD_DRIVER.\n");
		return false;
	}

	CloseHandle(n1);
	return true;
}
bool elevate_debug()
{
	TOKEN_PRIVILEGES priv;
	HANDLE n1;
	LUID luid;

	if(!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY, &n1))
	{
		printf(" [+] Impossible d'obtenir les droits SE_DEBUG.\n");
		return false;
	}

	LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid);
	priv.PrivilegeCount=1;
	priv.Privileges[0].Luid=luid;
	priv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	if(!AdjustTokenPrivileges(n1, FALSE, &priv, sizeof(priv), NULL, NULL))
	{
		printf(" [+] Impossible d'obtenir les droits SE_DEBUG.\n");
		return false;
	}

	CloseHandle(n1);
	return true;
}
