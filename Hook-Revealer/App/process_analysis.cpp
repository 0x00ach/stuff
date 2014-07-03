#include "hook_revealer.h"


void analysis::process_analysis()
{
	CLIENT_ID clinfo;
	OBJECT_ATTRIBUTES objectAttributes;

	printf(" [-] \"%s\" #%d [-", currentProcessName, currentPid);
	fprintf(currentFile, "400|%d|%s|||\n", currentPid, currentProcessName);

	clinfo.UniqueProcess = (HANDLE)currentPid;
	clinfo.UniqueThread = 0;

	nbLoadedModules=0;
	loadedModules=NULL;

	nbforwardeds=0;
	forwardeds=NULL;

	objectAttributes.Length=sizeof (OBJECT_ATTRIBUTES);
	objectAttributes.Attributes=0;
	objectAttributes.ObjectName=0;
	objectAttributes.RootDirectory=0;
	objectAttributes.SecurityDescriptor=0;
	objectAttributes.SecurityQualityOfService=0;

	if(myNtOpenProcess(&currentProcessHandle, PROCESS_ALL_ACCESS, &objectAttributes, &clinfo)!=STATUS_SUCCESS)
	{
		printf("!]\n");
		fprintf(currentFile, "602|%d|||Could not open process|\n", currentPid);
		return;
	}
	
	pebAnalysisAndLoadModules();
	printf("-");
	
	analyse_modules();

	deleteForwardeds();
	deleteModules();

	CloseHandle(currentProcessHandle);
	printf("-]\n");
}


void analysis::deleteForwardeds()
{
	if(nbforwardeds!=0 && forwardeds!=NULL)
	{
		for(int i=0; i<nbforwardeds; i++)
		{
			if(forwardeds[i] != NULL)
			{
				if(forwardeds[i]->functionName != NULL)
				{
					delete[] forwardeds[i]->functionName;
					forwardeds[i]->functionName=NULL;
				}
				delete forwardeds[i];
				forwardeds[i]=NULL;
			}
		}
		free(forwardeds);
		forwardeds=NULL;
		nbforwardeds=0;
	}
}