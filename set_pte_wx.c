// gets the PTE for the page using physical addresses (also implements the PFN db technique, but does not perform any modification),
// sets the +W bit and unsets the NX bit
NTSTATUS SetPTEWX(
	PVOID page
)
{
	PHYSICAL_ADDRESS pPage;
	UCHAR debug_msg[DEBUG_MESSAGE_LENGTH];
	ULONGLONG addr;
	PMMPFN ppfn;

	DbgPrint("\t[-] MMPFN -> PteLong update\r\n");
	pPage = MmGetPhysicalAddress(page);
	// convert to PFN
	pPage.QuadPart = pPage.QuadPart >> 12;
	if (NT_SUCCESS(RtlStringCbPrintfA((NTSTRSAFE_PSTR)debug_msg, DEBUG_MESSAGE_LENGTH, (NTSTRSAFE_PCSTR) "\t\tPFN: 0x%I64x\r\n", pPage.QuadPart))) {
		DbgPrint(debug_msg);
	}
	// get the MMPFN entry ptr
	addr = pPage.QuadPart + pPage.QuadPart + pPage.QuadPart;
	addr = addr << 4;
	addr = addr + 0xFFFFFA8000000000;
	ppfn = (PMMPFN)addr;
	if (NT_SUCCESS(RtlStringCbPrintfA((NTSTRSAFE_PSTR)debug_msg, DEBUG_MESSAGE_LENGTH, (NTSTRSAFE_PCSTR) "\t\tMMPFN addr: 0x%I64x\r\n", ppfn))) {
		DbgPrint(debug_msg);
	}
	// display the MMPFN entry ptr
	if (NT_SUCCESS(RtlStringCbPrintfA((NTSTRSAFE_PSTR)debug_msg, DEBUG_MESSAGE_LENGTH, (NTSTRSAFE_PCSTR) "\t\tMMPTE addr: 0x%I64x\r\n", (ULONGLONG)(ppfn->pMMPTE)))) {
		DbgPrint(debug_msg);
	}
	if ((ULONGLONG)(ppfn->pMMPTE) != 0)
	{
		// display the PTE entry :]
		if (NT_SUCCESS(RtlStringCbPrintfA((NTSTRSAFE_PSTR)debug_msg, DEBUG_MESSAGE_LENGTH, (NTSTRSAFE_PCSTR) "\t\tORIGINAL PTE DATA: 0x%I64x\r\n", *(PULONGLONG)(ppfn->pMMPTE)))) {
			DbgPrint(debug_msg);
		}

		//	DISABLED: the PFN db is not documented, and the direct PTE access is much more reliable, and I need to handle several corner cases within the MMPFN entries
		/*
		// let's set the +W bit
		*(PULONGLONG)(ppfn->pMMPTE) = *(PULONGLONG)(ppfn->pMMPTE) | 2;
		// and remove the NX bit
		*(PULONGLONG)(ppfn->pMMPTE) = *(PULONGLONG)(ppfn->pMMPTE) & 0x7FFFFFFFFFFFFFFF;
		*/
	}
	

	// now comes the "real" PTE part (I don't know why the PFN db one is not the same... anyway, let's patch it too)

	DbgPrint("\t[-] 'Real' PTE update\r\n");
	addr = __readcr3();
	pPage.QuadPart = addr + (sizeof(ULONGLONG) * (((ULONGLONG)page >> 0x27) & 0x1FF));
	if (NT_SUCCESS(RtlStringCbPrintfA((NTSTRSAFE_PSTR)debug_msg, DEBUG_MESSAGE_LENGTH, (NTSTRSAFE_PCSTR) "\t\tPML4E: %I64x\r\n", pPage.QuadPart))) {
		DbgPrint(debug_msg);
	}
	addr = (ULONGLONG)MmMapIoSpace(pPage, sizeof(ULONGLONG), MmNonCached);
	if (addr == 0)
	{
		DbgPrint("\t\tPHYSICAL READ ERROR\r\n");
		return STATUS_INVALID_ADDRESS;
	}

	addr = *(PULONGLONG)addr & 0xFFFFFFFFFF000;
	pPage.QuadPart = addr + (sizeof(ULONGLONG) * (((ULONGLONG)page >> 0x1E) & 0x1FF));
	if (NT_SUCCESS(RtlStringCbPrintfA((NTSTRSAFE_PSTR)debug_msg, DEBUG_MESSAGE_LENGTH, (NTSTRSAFE_PCSTR) "\t\tPDPE: %I64x\r\n", pPage.QuadPart))) {
		DbgPrint(debug_msg);
	}
	addr = (ULONGLONG)MmMapIoSpace(pPage, sizeof(ULONGLONG), MmNonCached);
	if (addr == 0)
	{
		DbgPrint("\t\tPHYSICAL READ ERROR\r\n");
		return STATUS_INVALID_ADDRESS;
	}

	addr = *(PULONGLONG)addr & 0xFFFFFFFFFF000;
	pPage.QuadPart = addr + (sizeof(ULONGLONG) * (((ULONGLONG)page >> 0x15) & 0x1FF));
	if (NT_SUCCESS(RtlStringCbPrintfA((NTSTRSAFE_PSTR)debug_msg, DEBUG_MESSAGE_LENGTH, (NTSTRSAFE_PCSTR) "\t\tPDE: %I64x\r\n", pPage.QuadPart))) {
		DbgPrint(debug_msg);
	}
	addr = (ULONGLONG)MmMapIoSpace(pPage, sizeof(ULONGLONG), MmNonCached);
	if (addr == 0)
	{
		DbgPrint("\t\tPHYSICAL READ ERROR\r\n");
		return STATUS_INVALID_ADDRESS;
	}

	addr = *(PULONGLONG)addr & 0xFFFFFFFFFF000;
	pPage.QuadPart = addr + (sizeof(ULONGLONG) * (((ULONGLONG)page >> 0xC) & 0x1FF));
	if (NT_SUCCESS(RtlStringCbPrintfA((NTSTRSAFE_PSTR)debug_msg, DEBUG_MESSAGE_LENGTH, (NTSTRSAFE_PCSTR) "\t\tPTE: %I64x\r\n", pPage.QuadPart))) {
		DbgPrint(debug_msg);
	}
	addr = (ULONGLONG)MmMapIoSpace(pPage, sizeof(ULONGLONG), MmNonCached);
	if (addr == 0)
	{
		DbgPrint("\t\tPHYSICAL READ ERROR\r\n");
		return STATUS_INVALID_ADDRESS;
	}

	// display the PTE entry before change :]
	if (NT_SUCCESS(RtlStringCbPrintfA((NTSTRSAFE_PSTR)debug_msg, DEBUG_MESSAGE_LENGTH, (NTSTRSAFE_PCSTR) "\t\tORIGINAL PTE DATA: 0x%I64x\r\n", *(PULONGLONG)addr))) {
		DbgPrint(debug_msg);
	}
	// let's set the +W bit
	*(PULONGLONG)(addr) = *(PULONGLONG)(addr) | 2;
	// and remove the NX bit
	*(PULONGLONG)(addr) = *(PULONGLONG)(addr) & 0x7FFFFFFFFFFFFFFF;

	// display the PTE entry before change :]
	if (NT_SUCCESS(RtlStringCbPrintfA((NTSTRSAFE_PSTR)debug_msg, DEBUG_MESSAGE_LENGTH, (NTSTRSAFE_PCSTR) "\t\tNEW PTE DATA: 0x%I64x\r\n", *(PULONGLONG)addr))) {
		DbgPrint(debug_msg);
	}

	return STATUS_SUCCESS;
}
