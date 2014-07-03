#include "hook_revealer.h"

int main(int argc, char* argv[])
{
	analysis* a;

	if(argc > 1)
		a = new analysis(argv[1]);
	else	
		a = new analysis("report.txt");

	delete a;

	return 0;
}

analysis::analysis(char* filename)
{
	printf("==== Hook revealer started ====\n\n");
	if(fopen_s(&currentFile, filename, "w")!=0)
	{
		printf("[+] Could not create %s file. Analysis aborted.\n", filename);
		system("pause");
		return;
	}
	else
	{
		printf("[+] Saving analysis report in %s file.\n", filename);
	}
	
	printf("[+] Configuration [-");
	elevate_debug();
	printf("-");
	initiateNtEmulations();
	printf("-");
	loadSystem32Dlls();
	if(strcmp(filename, "ring0.txt"))
	{
		printf("-]\n[+] Ring 3 analysis started, please wait...\n");
		fprintf(currentFile, "100|||||\n");
		analyseProcesses();
	}
	else
		printf("-]\n");
	printf("[+] Ring 0 analysis started\n");
	fprintf(currentFile, "200|||||\n");
	ring0analysis();
	printf("[+] Analysis completed!\n");
	fclose(currentFile);
	printf("[+] %s saved successfully.\n");
	system("pause");

}

analysis::analysis()
{
}