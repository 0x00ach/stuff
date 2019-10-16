BOOL SuDoSu()
{
	HANDLE hToken;
	LPCTSTR priv;
	TOKEN_PRIVILEGES tp;
	TOKEN_ELEVATION elevation;
	DWORD dwSize;
	LUID luid;
	BOOL rval = FALSE;
	OSVERSIONINFOW osver;
	PSID pAdministratorsGroup = NULL;
	BOOL isRunAsAdmin, isElevated;
	SHELLEXECUTEINFOA sei = { sizeof(sei) };
	char current_exe_path[MAX_PATH];

	// >= Vista
	if (GetVersionEx(&osver) && osver.dwMajorVersion >= 6)
		return TRUE;

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &hToken)) {
		goto end;
	}

	if (!GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &dwSize)) {
		goto endCloseToken;
	}
	
	isElevated = elevation.TokenIsElevated;

	SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
	if (!AllocateAndInitializeSid(
		&NtAuthority,
		2,
		SECURITY_BUILTIN_DOMAIN_RID,
		DOMAIN_ALIAS_RID_ADMINS,
		0, 0, 0, 0, 0, 0,
		&pAdministratorsGroup))
		goto endCloseToken;

	if (!CheckTokenMembership(NULL, pAdministratorsGroup, &isRunAsAdmin)) {
		goto endCloseSid;
	}

	// ADMIN + ELEVATED, OK!
	if (isRunAsAdmin == TRUE && isElevated == TRUE) {
		rval = TRUE;
		goto endCloseSid;
	}

	printf("Restarting process to get admin rights\n");
	if (GetModuleFileNameA(NULL, current_exe_path, MAX_PATH) != 0) {
		sei.lpVerb = "runas";
		sei.lpFile = current_exe_path;
		sei.nShow = SW_NORMAL;

		if (ShellExecuteExA(&sei) == TRUE) {
			TerminateProcess(GetCurrentProcess(), 0);
			goto endCloseSid;
		}
		printf("Cannot restart with administrative rights!\n");
	}

endCloseSid:
	FreeSid(pAdministratorsGroup);
endCloseToken:
	CloseHandle(hToken);

end:
	return rval;
}
