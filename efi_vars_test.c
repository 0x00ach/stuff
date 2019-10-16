#include <efi.h>
#include <efilib.h>
#include <efi.h>
#include <efilib.h>

EFI_STATUS delete_efi_var(EFI_SYSTEM_TABLE * SystemTable, CHAR16* varname, EFI_GUID guid)
{
	return SystemTable->RuntimeServices->SetVariable(varname, &guid, 0, 0, NULL);
}

EFI_STATUS print_efi_var(EFI_SYSTEM_TABLE * SystemTable, CHAR16* varname, EFI_GUID guid)
{
	CHAR16 data[256];
	UINT32 attr, i;
	UINTN data_size;
	EFI_STATUS status;
	UINTN Event;

	data_size = 256;
	attr = 0;
	i = 0;
	status = EFI_SUCCESS;
	Event = 0;

	ZeroMem(data, data_size);

	uefi_call_wrapper(SystemTable->ConOut->ClearScreen, 1, SystemTable->ConOut);

	status = SystemTable->RuntimeServices->GetVariable(varname, &guid, &attr, &data_size, &data);
	if (status == EFI_BUFFER_TOO_SMALL)
	{
		Print(L"    ERROR :: BUFFER TOO SMALL (need at least %x bytes)\n", data_size);	// should alloc/retry
	}
	else if (EFI_ERROR(status))
	{
		Print(L"    ERROR :: %x\n", status);
	}
	else
	{
		Print(L"    HEXDUMP:\n");
		for (i = 0; i < data_size; i++)
		{
			if (i % 0x10 == 0)
				Print(L"\n%.2x  ", i);
			Print(L"%.2x ", *((CHAR8*)((UINTN)data + i)));
		}
		Print(L"\n");
	}

	return status;
}

EFI_STATUS enumerate_boot_vars(EFI_SYSTEM_TABLE *SystemTable, BOOLEAN dump_contents, BOOLEAN delete_secureboot_vars)
{

	EFI_GUID guid;
	UINTN i, data_size;
	EFI_STATUS status;
	UINTN Event;
	CHAR16 data[256];

	i = 0;
	status = EFI_SUCCESS;
	data_size = sizeof(data);
	
	ZeroMem(data, data_size);

	Print(L"ENUMERATE START\n");
	status = SystemTable->RuntimeServices->GetNextVariableName(&data_size, data, &guid);
	while (status == EFI_SUCCESS || status == EFI_BUFFER_TOO_SMALL)
	{
		if (status == EFI_BUFFER_TOO_SMALL)
		{
			Print(L"Too small!\n");
		}
		else
		{
			Print(L"%s (%x-%x-%x-%x)\n", data, guid.Data1, guid.Data2, guid.Data3, guid.Data4);

			i = i + 1;
			if (i % 0x10 == 0 || dump_contents == TRUE)
			{
				if (dump_contents == TRUE)
					print_efi_var(SystemTable, data, guid);

				Print(L"Press any key to continue.\n");
				SystemTable->ConIn->Reset(SystemTable->ConIn, FALSE);
				SystemTable->BootServices->WaitForEvent(1, &SystemTable->ConIn->WaitForKey, &Event);
				uefi_call_wrapper(SystemTable->ConOut->ClearScreen, 1, SystemTable->ConOut);
			}
			if (delete_secureboot_vars == TRUE &&
				guid.Data1 == 0x77FA9ABD &&
				guid.Data2 == 0x0359 &&
				guid.Data3 == 0x4D32)
			{
				delete_efi_var(SystemTable, data, guid);
			}

			data_size = sizeof(data);
			status = SystemTable->RuntimeServices->GetNextVariableName(&data_size, data, &guid);
		}
	}

	Print(L"Press any key to continue.\n");
	SystemTable->ConIn->Reset(SystemTable->ConIn, FALSE);
	SystemTable->BootServices->WaitForEvent(1, &SystemTable->ConIn->WaitForKey, &Event);
	uefi_call_wrapper(SystemTable->ConOut->ClearScreen, 1, SystemTable->ConOut);
	return EFI_SUCCESS;
}

EFI_STATUS efi_main(EFI_HANDLE ImageHandle, EFI_SYSTEM_TABLE *SystemTable)
{
	UINTN Event;

	InitializeLib(ImageHandle, SystemTable);
	
	Print(L"=== START ===\n");
	enumerate_boot_vars(SystemTable, TRUE, FALSE);

	Print(L"=== END ===\n");
	Print(L"%EPress any key to exit.%N\n");
	SystemTable->ConIn->Reset(SystemTable->ConIn, FALSE);
	SystemTable->BootServices->WaitForEvent(1, &SystemTable->ConIn->WaitForKey, &Event);
		

	return EFI_SUCCESS;
}
