@echo off
if "%2"=="" (
	echo "Utilisation: %0 <executable> <outputdir>"
) else (
	echo "Telechargement des symboles de %1"
	symchk.exe /if %1 /s SRV*%SYSTEMDRIVE%\SYMBOLS*https://msdl.microsoft.com/download/symbols /op /ocx %2
)
