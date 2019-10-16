#define _FIND_OVERFLOWS 1
#define _DEBUG 1

// should also set page guards
PVOID MemAlloc(SIZE_T size) {
#if defined(_DEBUG) && defined(_FIND_OVERFLOWS)
	PVOID npage;
	SIZE_T sz;

	sz = size + 0x1000 & 0xFFFFFFFFFFFFF000;
	npage = VirtualAlloc(NULL, sz, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	return (PVOID)((SIZE_T)npage + sz - size);
#else
	return HeapAlloc(GetProcessHeap(), 0, size);
#endif
}
BOOL MemFree(PVOID addr) {
#if defined(_DEBUG) && defined(_FIND_OVERFLOWS)
	return VirtualFree(addr, 0, MEM_RELEASE);
#else
	return HeapFree(GetProcessHeap(), 0, addr);
#endif
}
