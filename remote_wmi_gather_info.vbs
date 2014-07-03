Option Explicit

'ID des ruches de registre
Const HKR = &H80000000
Const HKCU = &H80000001
Const HKLM = &H80000002
Const HKU = &H80000003
Const HKCC = &H80000005

Function Ping(strHost)
    Dim oPing, oRetStatus, bReturn
    Set oPing = GetObject("winmgmts:{impersonationLevel=impersonate}").ExecQuery("select * from Win32_PingStatus where address='" & strHost & "'")
	Ping = false
    For Each oRetStatus In oPing
        If oRetStatus.StatusCode = 0 Then
            Ping = True
		End If
    Next
End Function


Dim args
Set args  = Wscript.Arguments
Dim sidList, curValue, objit, resFind, listKeys, keyName, curSid, fullnames, fullname, domain, user, password, computer, hkuscan
Dim objSWbemLocator, objSWbemServices, omsdefault, omscimv2, fullLogin, cpt, force
force = false
hkuscan = true
domain =""
computer = ""
user = ""
password = ""

Wscript.Echo "		============ MACHINE SCANNER ==========="
For cpt = 0 to args.count -1
	If args(cpt) = "-h" Then
		Wscript.Echo "Usage : cscript machinescanner.vbs -d DOMAIN -u USERNAME -p PASSWORD -m machine [-f] [-h]"
		Wscript.Echo "-d/u/p : administrator user's domain, username and password"
		Wscript.Echo "-m machine: IP address or domain name"
		Wscript.Echo "-f : force scan even if the machine can't be pinged"
		Wscript.Echo "-h : display this message"
		Wscript.Echo "-k : disables the HKU scan (can be long)"
		Wscript.Echo "		===================================="
		Wscript.Quit 0
	End If
	If args(cpt) = "-d" Then
		domain = args(cpt+1)
	End If
	If args(cpt) = "-u" Then
		user = args(cpt+1)
	End If
	If args(cpt) = "-p" Then
		password = args(cpt+1)
	End If
	If args(cpt) = "-k" Then
		hkuscan = false
	End If
	If args(cpt) = "-m" Then
		computer = args(cpt+1)
	End If
	If args(cpt) = "-f" Then
		force = 1
	End If
Next

If user = "" Then
	Wscript.Echo "[!] Please specify the username"
	Wscript.Quit -1
End If
If  computer = "" Then
	Wscript.Echo "[!] Please specify one machine to scan"
	Wscript.Quit -1
End If


If not force Then
	If Ping(computer) = false Then
		Wscript.Echo "[-] " & domain & "\" & computer & " IS NOT REACHABLE."
		Wscript.Quit 0
	End If
End If
	
Set objSWbemLocator = CreateObject("WbemScripting.SWbemLocator")

If domain = "" Then
	fullLogin = user
Else
	fullLogin = domain & "\" & user
End If

err.clear
Set objSWbemServices = objSWbemLocator.ConnectServer(computer, "root\default", fullLogin, password)
objSWbemServices.Security_.ImpersonationLevel = 3
Set omsdefault = objSWbemServices.Get("stdregprov")
Set omscimv2 = objSWbemLocator.ConnectServer(computer, "root\cimv2", fullLogin, password)
omscimv2.Security_.ImpersonationLevel = 3

If err.Number <> 0 Then
	Wscript.Echo "[-] " & domain & "\" & computer & " IS NOT REACHABLE."
	Wscript.Quit 0
End If

Set fullnames = omscimv2.ExecQuery("SELECT Name FROM Win32_ComputerSystem")
For Each objit in fullnames
	fullname = objit.Name
Next

Wscript.Echo "==== " & domain & "\" & computer & " (" & fullname & ") SCAN ===="
Wscript.Echo ""
Wscript.Echo "############## C:\RECYCLER FILES ##############"
Set resFind = omscimv2.ExecQuery("select name, CreationDate from CIM_DataFile where path = '\\RECYCLER\\'")
If not IsNull(resFind) Then
	For Each objit in resFind
		Wscript.Echo "	" & objit.Name & " (" & objit.CreationDate & ")"
	Next
End If

Wscript.Echo ""
Wscript.Echo "############## C:\WINDOWS\PREFETCH\ FILES ##############"
Set resFind = omscimv2.ExecQuery("select name, CreationDate from CIM_DataFile where path = '\\WINDOWS\\Prefetch\\'")
If not IsNull(resFind) Then
	For Each objit in resFind
		Wscript.Echo "	" & objit.Name & " (" & objit.CreationDate & ")"
	Next
End If

Wscript.Echo ""
Wscript.Echo "############## PSEXEC EVENTS ##############"
' Detection dans les eventLogs
Set eventsSys = omscimv2.ExecQuery("select TimeWritten, User from win32_ntlogevent where logfile='system' and (EventCode='7036' or EventCode='7035') and Message like '%psexe%'")
set eventsSec = omscimv2.ExecQuery("select TimeWritten, User from win32_ntlogevent where logfile='security' and EventCode='4697' and Message like '%psexe%'")
' Affichage des résulatats
For Each objit in eventsSys
	Wscript.Echo "PSEXESVC service started on " & objit.TimeWritten & " by : " & objit.User
Next
For Each objit in eventsSec
	Wscript.Echo "PSEXESVC service installed on " & objit.TimeWritten & " by : " & objit.User
Next

Wscript.Echo ""
Wscript.Echo "############## HKLM RUN KEYS ##############"
omsdefault.EnumValues HKLM, "Software\Microsoft\Windows\CurrentVersion\Run", listKeys
For Each keyName in listKeys
	omsdefault.GetStringValue HKLM, "Software\Microsoft\Windows\CurrentVersion\Run", keyName, curValue
	Wscript.Echo "	" & keyname & " : " & curValue
Next

If hkuscan Then
	Set sidList = omscimv2.ExecQuery("select SID from win32_useraccount")
	Wscript.Echo ""
	Wscript.Echo "############## HKU RUN KEYS ##############"
	For Each curSid in sidList
		Wscript.Echo "SID : " & curSid.SID
		omsdefault.EnumValues HKU, curSid.SID & "\Software\Microsoft\Windows\CurrentVersion\Run", listKeys
		For Each keyName in listKeys
			omsdefault.GetStringValue HKU, curSid.SID & "\Software\Microsoft\Windows\CurrentVersion\Run", keyName, curValue
			Wscript.Echo "	" & keyname & " : " & curValue
		Next
	Next
End If

Wscript.Echo ""
Wscript.Echo "############### ACTIVE SETUP INSTALLED COMPONENTS ###############"
omsdefault.EnumKey HKLM, "SOFTWARE\Microsoft\Active Setup\Installed Components", listKeys
For Each keyName in listKeys
	omsdefault.GetStringValue HKLM, "SOFTWARE\Microsoft\Active Setup\Installed Components\" & keyName, "StubPath", curValue
	If not IsNull(curValue) Then		
		Wscript.Echo "Active Setup " & keyName & " : " & curValue
	End If
Next

Wscript.Echo ""
Wscript.Echo "############### REGISTERED SERVICES ###############"
omsdefault.EnumKey HKLM, "SYSTEM\\CurrentControlSet\\Services", listKeys
For Each keyName in listKeys	
	Wscript.Echo "Service : " & keyName
Next

Wscript.Echo ""
Wscript.Echo "############### Files in RECYCLER folders ###############"
Set resFind = omscimv2.ExecQuery("select name, CreationDate from CIM_DataFile where path = '\\RECYCLER\\'")
If not IsNull(resFind) Then
	For Each objit in resFind
		WScript.Echo "RECYCLER folder file : " & objit.Name & " (" & objit.CreationDate & ")"
	Next
End If

Wscript.Echo ""
Wscript.Echo "=== FINISHED ==="