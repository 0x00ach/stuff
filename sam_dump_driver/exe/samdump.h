#include <windows.h>
#include <stdio.h>
#include <string>

//Types de status du driver
#define DRIVER_NOT_INSTALLED 0x1
#define DRIVER_STARTED 0x2
#define DRIVER_STOPPED 0x3
//defines, max_path, etc.
#define MAX_KEY_LENGTH 255
#define MAX_VALUE_NAME 16383

//IOCTL / IRP
#define SIOCTL_TYPE 40000
#define IOCTL_RETRIEVE_RID\
    CTL_CODE( SIOCTL_TYPE, 0x902, METHOD_BUFFERED, FILE_READ_DATA|FILE_WRITE_DATA)
#define IOCTL_RETRIEVE_F_BYTES\
    CTL_CODE( SIOCTL_TYPE, 0x903, METHOD_BUFFERED, FILE_READ_DATA|FILE_WRITE_DATA)
#define IOCTL_RETRIEVE_RID_V_BYTES\
    CTL_CODE( SIOCTL_TYPE, 0x904, METHOD_BUFFERED, FILE_READ_DATA|FILE_WRITE_DATA)
#define IOCTL_RETRIEVE_SYSKEY\
    CTL_CODE( SIOCTL_TYPE, 0x905, METHOD_BUFFERED, FILE_READ_DATA|FILE_WRITE_DATA)

//globales pour la gestion du service
extern SC_HANDLE manager;
extern SC_HANDLE service;

//clean des handles
void sCCleanHandles();
//contrôle du service
bool stop_service();
bool start_service();
//install/uninstall du driver
bool remove_driver();
bool install_driver();
//check du status
int driverStatus();
//dump de la base SAM
void dumpHashes();
bool getRIDs();
//dump de la syskey
void dumpSyskey();
void dumpClassVal(PWSTR val, PWSTR key);