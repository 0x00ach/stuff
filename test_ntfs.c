#include <Windows.h>
#include <stdio.h>

#define SECTOR_SIZE			0x200
#define SECTOR_SEARCH_MAX	1000
#define NTFS_MAGIC			0x5346544e
#define NTFS_MAGIC_OFFSET	3
#define SECTOR_MAX_READ		100
#pragma pack(push,1)


// cf. https://ultradefrag.net/doc/man/ntfs/NTFS_On_Disk_Structure.pdf
// cf. https://www.ivanlef0u.tuxfamily.org/?p=76
// cf. https://github.com/DeDf/ParseNTFS/blob/master/ntfs.h

typedef struct _NTFS5_BOOT_RECORD {
	BYTE	_jmpcode[3];
	CHAR	cOEMID[8];
	WORD	wBytesPerSector;
	BYTE	bSectorsPerCluster;
	WORD	wSectorsReservedAtBegin;
	BYTE	Mbz1;
	WORD	Mbz2;
	WORD	Reserved1;
	BYTE	bMediaDescriptor;
	WORD	Mbz3;
	WORD	wSectorsPerTrack;
	WORD	wSides;
	DWORD	dwSpecialHiddenSectors;
	DWORD	Reserved2;
	DWORD	Reserved3;
	UINT64	TotalSectors;
	LARGE_INTEGER	MftStartLcn;
	UINT64	Mft2StartLcn;
	DWORD	ClustersPerFileRecord;
	DWORD	ClustersPerIndexBlock;
	UINT64	VolumeSerialNumber;
	BYTE	_loadercode[430];
	WORD	wSignature;
} NTFS5_BOOT_RECORD, *PNTFS5_BOOT_RECORD;
#pragma pack(pop)

typedef struct {
	ULONG Type;
	USHORT UsaOffset;
	USHORT UsaCount;
	USN Usn;
} NTFS_RECORD_HEADER, *PNTFS_RECORD_HEADER;

typedef struct {
	NTFS_RECORD_HEADER RecHdr;    // An NTFS_RECORD_HEADER structure with a Type of 'FILE'.
	USHORT SequenceNumber;        // Sequence number - The number of times
	// that the MFT entry has been reused.
	USHORT LinkCount;             // Hard link count - The number of directory links to the MFT entry
	USHORT AttributeOffset;       // Offset to the first Attribute - The offset, in bytes,
	// from the start of the structure to the first attribute of the MFT
	USHORT Flags;                 // Flags - A bit array of flags specifying properties of the MFT entry
	// InUse 0x0001 - The MFT entry is in use
	// Directory 0x0002 - The MFT entry represents a directory
	ULONG BytesInUse;             // Real size of the FILE record - The number of bytes used by the MFT entry.
	ULONG BytesAllocated;         // Allocated size of the FILE record - The number of bytes
	// allocated for the MFT entry
	ULONGLONG BaseFileRecord;     // reference to the base FILE record - If the MFT entry contains
	// attributes that overflowed a base MFT entry, this member
	// contains the file reference number of the base entry;
	// otherwise, it contains zero
	USHORT NextAttributeNumber;   // Next Attribute Id - The number that will be assigned to
	// the next attribute added to the MFT entry.
	USHORT Pading;                // Align to 4 byte boundary (XP)
	ULONG MFTRecordNumber;        // Number of this MFT Record (XP)
	USHORT UpdateSeqNum;          //
} FILE_RECORD_HEADER, *PFILE_RECORD_HEADER;
typedef enum {
	AttributeStandardInformation = 0x10,
	AttributeAttributeList = 0x20,
	AttributeFileName = 0x30,
	AttributeObjectId = 0x40,
	AttributeSecurityDescriptor = 0x50,
	AttributeVolumeName = 0x60,
	AttributeVolumeInformation = 0x70,
	AttributeData = 0x80,
	AttributeIndexRoot = 0x90,
	AttributeIndexAllocation = 0xA0,
	AttributeBitmap = 0xB0,
	AttributeReparsePoint = 0xC0,
	AttributeEAInformation = 0xD0,
	AttributeEA = 0xE0,
	AttributePropertySet = 0xF0,
	AttributeLoggedUtilityStream = 0x100
} ATTRIBUTE_TYPE, *PATTRIBUTE_TYPE;
char* attributes2name[] = { "", "AttributeStandardInformation", "AttributeAttributeList", "AttributeFileName", "AttributeObjectId", "AttributeSecurityDescriptor", "AttributeVolumeName", "AttributeVolumeInformation", "AttributeData", "AttributeIndexRoot", "AttributeIndexAllocation", "AttributeBitmap", "AttributeReparsePoint", "AttributeEAInformation", "AttributeEA", "AttributePropertySet", "AttributeLoggedUtilityStream"};
typedef struct {
	ATTRIBUTE_TYPE AttributeType;
	ULONG Length;
	BOOLEAN Nonresident;
	UCHAR NameLength;
	USHORT NameOffset;
	USHORT Flags; // 0x0001 = Compressed
	USHORT AttributeNumber;
} ATTRIBUTE, *PATTRIBUTE;
typedef struct _RESIDENT_ATTRIBUTE {
	ATTRIBUTE	Attribute;
	ULONG		ValueLength;
	USHORT		ValueOffset;
	USHORT		Flags; // 0x0001 = Indexed
} RESIDENT_ATTRIBUTE, *PRESIDENT_ATTRIBUTE;
typedef struct {
	ATTRIBUTE Attribute;
	ULONGLONG LowVcn;
	ULONGLONG HighVcn;
	USHORT RunArrayOffset;
	UCHAR CompressionUnit;
	UCHAR AlignmentOrReserved[5];
	ULONGLONG AllocatedSize;
	ULONGLONG DataSize;
	ULONGLONG InitializedSize;
	ULONGLONG CompressedSize; // Only when compressed
} NONRESIDENT_ATTRIBUTE, *PNONRESIDENT_ATTRIBUTE;
typedef struct {
	ULONGLONG CreationTime;
	ULONGLONG ChangeTime;
	ULONGLONG LastWriteTime;
	ULONGLONG LastAccessTime;
	ULONG FileAttributes;
	ULONG AlignmentOrReservedOrUnknown[3];
	ULONG QuotaId; // NTFS 3.0 only
	ULONG SecurityId; // NTFS 3.0 only
	ULONGLONG QuotaCharge; // NTFS 3.0 only
	USN Usn; // NTFS 3.0 only
} STANDARD_INFORMATION, *PSTANDARD_INFORMATION;
typedef struct {
	ATTRIBUTE_TYPE AttributeType;
	USHORT Length;
	UCHAR NameLength;
	UCHAR NameOffset;
	ULONGLONG LowVcn;
	ULONGLONG FileReferenceNumber;
	USHORT AttributeNumber;
	USHORT AlignmentOrReserved[3];
} ATTRIBUTE_LIST, *PATTRIBUTE_LIST;
typedef struct {
	ULONGLONG DirectoryFileReferenceNumber;
	ULONGLONG CreationTime; // Saved when filename last changed
	ULONGLONG ChangeTime; // ditto
	ULONGLONG LastWriteTime; // ditto
	ULONGLONG LastAccessTime; // ditto
	ULONGLONG AllocatedSize; // ditto
	ULONGLONG DataSize; // ditto
	ULONG FileAttributes; // ditto
	ULONG AlignmentOrReserved;
	UCHAR NameLength;
	UCHAR NameType; // 0x01 = Long, 0x02 = Short
	WCHAR Name[1];
} FILENAME_ATTRIBUTE, *PFILENAME_ATTRIBUTE;
typedef struct {
	GUID ObjectId;
	union {
		struct {
			GUID BirthVolumeId;
			GUID BirthObjectId;
			GUID DomainId;
		};
		UCHAR ExtendedInfo[48];
	};
} OBJECTID_ATTRIBUTE, *POBJECTID_ATTRIBUTE;
typedef struct {
	ULONG EntriesOffset;
	ULONG IndexBlockLength;
	ULONG AllocatedSize;
	ULONG Flags; // 0x00 = Small directory, 0x01 = Large directory
} DIRECTORY_INDEX, *PDIRECTORY_INDEX;
typedef struct {
	ULONGLONG FileReferenceNumber;
	USHORT Length;
	USHORT AttributeLength;
	ULONG Flags; // 0x01 = Has trailing VCN, 0x02 = Last entry
	// FILENAME_ATTRIBUTE Name;
	// ULONGLONG Vcn; // VCN in IndexAllocation of earlier entries
} DIRECTORY_ENTRY, *PDIRECTORY_ENTRY;
typedef struct {
	ATTRIBUTE_TYPE Type;
	ULONG CollationRule;
	ULONG BytesPerIndexBlock;
	ULONG ClustersPerIndexBlock;
	DIRECTORY_INDEX DirectoryIndex;
} INDEX_ROOT, *PINDEX_ROOT;
typedef struct {
	NTFS_RECORD_HEADER Ntfs;
	ULONGLONG IndexBlockVcn;
	DIRECTORY_INDEX DirectoryIndex;
} INDEX_BLOCK_HEADER, *PINDEX_BLOCK_HEADER;

typedef struct _INDEX_HEADER {
	ULONG FirstIndexEntry;  
	ULONG FirstFreeByte;         
	ULONG BytesAvailable;      
	UCHAR Flags;              
	UCHAR Reserved[3];                            
} INDEX_HEADER, *PINDEX_HEADER;

typedef struct _MFT_SEGMENT_REFERENCE {
	ULONG SegmentNumberLowPart;                              
	USHORT SegmentNumberHighPart;    
	USHORT SequenceNumber;                                    

} MFT_SEGMENT_REFERENCE, *PMFT_SEGMENT_REFERENCE; 


typedef struct _DUPLICATED_INFORMATION {
	LONGLONG CreationTime;               
	LONGLONG LastModificationTime;     
	LONGLONG LastChangeTime;        
	LONGLONG LastAccessTime;      
	LONGLONG AllocatedLength;      
	LONGLONG FileSize;         
	ULONG FileAttributes;           
	USHORT PackedEaSize;      
	USHORT Reserved;                                              
} DUPLICATED_INFORMATION;                                         
typedef DUPLICATED_INFORMATION *PDUPLICATED_INFORMATION;
typedef MFT_SEGMENT_REFERENCE FILE_REFERENCE, *PFILE_REFERENCE;

#define FILE_NAME_NTFS                   (0x01)
#define FILE_NAME_DOS                    (0x02)

typedef struct _INDEX_ENTRY {
	ULONGLONG FileReferenceNumber;
	USHORT Length;             
	USHORT AttributeLength;  
	ULONG Flags;
	FILENAME_ATTRIBUTE FileName;
	ULONGLONG Vcn;
} INDEX_ENTRY;                                                      //  sizeof = 0x010
typedef INDEX_ENTRY *PINDEX_ENTRY;

#define INDEX_ENTRY_NODE                 (0x0001)
#define INDEX_ENTRY_END                  (0x0002)
#define INDEX_ENTRY_POINTER_FORM         (0x8000)


#define MFT_ENTRY_NUMBER 0

ULONG gBytesPerSector = 0;
ULONG gSectorsPerCluster = 0;
ULONG gOffset = 0;
BOOL ReadSector(HANDLE hFile, PBYTE data, ULONGLONG offset, BOOLEAN sectorOffset, ULONG dwCount) {
	ULONG dwSize;
	LARGE_INTEGER x;
	
	if (sectorOffset)
		offset = offset * SECTOR_SIZE;
	dwCount = dwCount * SECTOR_SIZE;

	offset += gOffset;

	if (offset & 0x8000000000000000)
		return FALSE;
	
	x.QuadPart = offset;

	SetFilePointer(hFile, x.LowPart, &x.HighPart, FILE_BEGIN);

	return ReadFile(hFile, data, dwCount, &dwSize, NULL);
}

ULONGLONG LcnToOffset(LONGLONG lcn) {
	return (ULONGLONG)(lcn * gBytesPerSector * gSectorsPerCluster);
}




void GetPartPTR(PBYTE first_sector, PDWORD StartOffset, PDWORD EndOffset, DWORD i) {

	PBYTE partition_table_ptr = first_sector + 0x1be + i * 0x10;

	*StartOffset = *(PDWORD)(partition_table_ptr + 8) * SECTOR_SIZE;
	*EndOffset = *StartOffset + *(PULONG)(partition_table_ptr + 0xC) * SECTOR_SIZE;
	printf("Start part %x\n", StartOffset);
	return ;
}

void ParseNtfsPartition(char* Path, ULONGLONG fileOffset) {

	HANDLE hFile;
	BYTE toto[SECTOR_MAX_READ*SECTOR_SIZE], toto2[SECTOR_SIZE];
	ULONG dwRead = 0;
	ULONG i = 0, j = 0,  ntfsOffset = 0, dataMaxSize = 0, dataReadSize = 0, neededSize = 0, dx = 0 , nodeSize = 0;
	PNTFS5_BOOT_RECORD pBootRecord;
	ULONGLONG MFTOffset = 0;
	PFILE_RECORD_HEADER FileRecord;
	PATTRIBUTE Attribute;
	PRESIDENT_ATTRIBUTE ResidentAttribute;
	PNONRESIDENT_ATTRIBUTE NonResidentAttribute;
	PFILENAME_ATTRIBUTE FileNameAttributePtr;
	PINDEX_ROOT IndexRootPtr;
	PINDEX_HEADER IndexHeaderPtr;
	PINDEX_ENTRY IndexEntryPtr;
	ULONG PtrStart, PtrEnd;

	hFile = CreateFileA(Path, GENERIC_READ, FILE_SHARE_WRITE | FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
	if (hFile == INVALID_HANDLE_VALUE){
		printf("Cannot open file!\n");
		return;
	}
	printf("%s opened!\n", Path);

	ReadSector(hFile, toto, 0, TRUE, 1);


	if (*(PULONG)(toto + NTFS_MAGIC_OFFSET) != NTFS_MAGIC) {

		printf("Not an NTFS part ptr, searching for NTFS part...\n");
		if (toto[0x1FE] == 0x55 && toto[0x1FF] == 0xAA) {
			printf("MBR disk found, walking partitions...\n");
			for (i = 0; i < 4; i++) {
				GetPartPTR(toto, &PtrStart, &PtrEnd, i);
				ReadSector(hFile, toto2, PtrStart, FALSE, 1);

				if (*(PULONG)(toto2 + NTFS_MAGIC_OFFSET) == NTFS_MAGIC) {
					printf("Found NTFS partition at offset %x to %x\n", PtrStart, PtrEnd);
					gOffset = PtrStart;
					memcpy(toto, toto2, SECTOR_SIZE);
					break;
				}
			}
		}
		
		if (PtrStart == 0) {

			for (i = 0; i <  SECTOR_SEARCH_MAX; i++) {
				ReadSector(hFile, toto, i, TRUE, 1);
				if (*(PULONG)(toto + NTFS_MAGIC_OFFSET) == NTFS_MAGIC) {
					gOffset = i * SECTOR_SIZE;
					break;
				}
			}

			if (gOffset == 0) {
				printf("Cannot find NTFS partition in file...\n");
				goto end;
			}

			printf("Found NTFS partition at sector %d\n", gOffset / SECTOR_SIZE);
		}
	}
	
	pBootRecord = (PNTFS5_BOOT_RECORD)toto;

	gBytesPerSector = pBootRecord->wBytesPerSector;
	gSectorsPerCluster = pBootRecord->bSectorsPerCluster;

	MFTOffset = LcnToOffset(pBootRecord->MftStartLcn.QuadPart);
	printf("$MFT offset: %x\n", MFTOffset);

	ReadSector(hFile, toto, MFTOffset, FALSE, 1);
	FileRecord = (PFILE_RECORD_HEADER)toto;

	dataReadSize = SECTOR_SIZE;
	dataMaxSize = 0;
	for (i = 0; i < 16; i++) {
		
		// do we need extra read ?
		// we have the FILE_RECORD_HEADER, but we want to also have the full size
		// and the next record header
		dataMaxSize += FileRecord->BytesAllocated + sizeof(FILE_RECORD_HEADER);
		while (dataMaxSize > dataReadSize) {
			ReadSector(hFile, toto + dataReadSize, MFTOffset + dataReadSize, FALSE, 1);
			dataReadSize += SECTOR_SIZE;
		}

		// print the file record data
		printf("MFT entry %d\n", i);
		printf("\tFlags: %d\n", FileRecord->Flags);
		printf("\tNextAttributeNumber: %d\n", FileRecord->NextAttributeNumber);
		printf("\tBytesAllocated: %d\n", FileRecord->BytesAllocated);

		// attributes
		printf("\tAttributes:\n");
		Attribute = (PATTRIBUTE)((SIZE_T)FileRecord + FileRecord->AttributeOffset);

		for (j = 0; j < FileRecord->NextAttributeNumber; j++) {

			printf("\t\tNumber: %d\n", Attribute->AttributeNumber);
			if (Attribute->AttributeType <= 0x100)
				printf("\t\t\tType: %x (%s)\n", Attribute->AttributeType, attributes2name[Attribute->AttributeType/ 0x10]);
			else
				printf("\t\t\tType: %x (unknown)\n", Attribute->AttributeType);
			printf("\t\t\tResident: %d\n", Attribute->Nonresident);

			if (Attribute->NameLength != 0) {
				printf("\t\t\tName: %.*S\n", Attribute->NameLength, (SIZE_T)Attribute + Attribute->NameOffset);
			}

			if (Attribute->Nonresident == TRUE) {
				NonResidentAttribute = (PNONRESIDENT_ATTRIBUTE)Attribute;
				// TODO, gl;hf :D
			}
			else {
				ResidentAttribute = (PRESIDENT_ATTRIBUTE)Attribute;
				if (ResidentAttribute->Attribute.AttributeType == AttributeFileName) {
					printf("\t\t\tFileName resident attribute data:\n");
					FileNameAttributePtr = (PFILENAME_ATTRIBUTE)((SIZE_T)ResidentAttribute + ResidentAttribute->ValueOffset);
					printf("\t\t\t\tNameType: %x\n", FileNameAttributePtr->NameType);
					printf("\t\t\t\tName: %.*S\n", FileNameAttributePtr->NameLength, FileNameAttributePtr->Name);
				}
        
				if (ResidentAttribute->Attribute.AttributeType == AttributeIndexRoot) {
					IndexRootPtr = (PINDEX_ROOT)((SIZE_T)ResidentAttribute + ResidentAttribute->ValueOffset);
					printf("\t\t\tINDEX_ROOT:\n");
					printf("\t\t\t\tBytesPerIndexBlock: %x\n", IndexRootPtr->BytesPerIndexBlock);
					printf("\t\t\t\tClustersPerIndexBlock: %x\n", IndexRootPtr->ClustersPerIndexBlock);
					printf("\t\t\t\tCollationRule: %x\n", IndexRootPtr->CollationRule);
					printf("\t\t\t\tType: %x\n", IndexRootPtr->Type);
					printf("\t\t\t\tDirectoryIndex.AllocatedSize: %x\n", IndexRootPtr->DirectoryIndex.AllocatedSize);
					printf("\t\t\t\tDirectoryIndex.EntriesOffset: %x\n", IndexRootPtr->DirectoryIndex.EntriesOffset);
					printf("\t\t\t\tDirectoryIndex.Flags: %x\n", IndexRootPtr->DirectoryIndex.Flags);
					printf("\t\t\t\tDirectoryIndex.IndexBlockLength: %x\n", IndexRootPtr->DirectoryIndex.IndexBlockLength);

					// SmallDirectory 0x0000 // Directory fits in index root
					// LargeDirectory 0x0001 // Directory overflows index root
					if (IndexRootPtr->DirectoryIndex.Flags == 0) {

						printf("\t\t\t\tDirectoryIndex.Entries:\n");

						IndexEntryPtr = (PINDEX_ENTRY)((SIZE_T)&IndexRootPtr->DirectoryIndex + IndexRootPtr->DirectoryIndex.EntriesOffset);
						dx = 0;
						nodeSize = 0;
						while (IndexEntryPtr->Flags != INDEX_ENTRY_END) {

							printf("\t\t\t\t\tDirectoryIndex.Entries.%d\n", dx);
							printf("\t\t\t\t\t\tAttributeLength: %x\n", IndexEntryPtr->AttributeLength);
							printf("\t\t\t\t\t\tLength: %x\n", IndexEntryPtr->Length);
							printf("\t\t\t\t\t\tFlags: %x\n", IndexEntryPtr->Flags);
							printf("\t\t\t\t\t\tFileReferenceNumber: %x\n", IndexEntryPtr->FileReferenceNumber);

							if (IndexEntryPtr->Flags == INDEX_ENTRY_NODE) {
								printf("\t\t\t\t\t\tFileName.DirectoryFileReferenceNumber: %x\n", IndexEntryPtr->FileName.DirectoryFileReferenceNumber);
								printf("\t\t\t\t\t\tFileName.NameLength: %x\n", IndexEntryPtr->FileName.NameLength);
								printf("\t\t\t\t\t\tFileName.FileName: %.*S\n", IndexEntryPtr->FileName.NameLength, &IndexEntryPtr->FileName.Name);
								printf("\t\t\t\t\t\tFileName.CreationTime: %x\n", IndexEntryPtr->FileName.CreationTime);
								printf("\t\t\t\t\t\tFileName.ChangeTime: %x\n", IndexEntryPtr->FileName.ChangeTime);
								printf("\t\t\t\t\t\tFileName.LastWriteTime: %x\n", IndexEntryPtr->FileName.LastWriteTime);
								printf("\t\t\t\t\t\tFileName.LastAccessTime: %x\n", IndexEntryPtr->FileName.LastAccessTime);
								printf("\t\t\t\t\t\tFileName.AllocatedSize: %x\n", IndexEntryPtr->FileName.AllocatedSize);
								printf("\t\t\t\t\t\tFileName.DataSize: %x\n", IndexEntryPtr->FileName.DataSize);
								printf("\t\t\t\t\t\tFileName.FileAttributes: %x\n", IndexEntryPtr->FileName.FileAttributes);
								printf("\t\t\t\t\t\tFileName.ParentDirectory.NameType: %x\n", IndexEntryPtr->FileName.NameType);
							}
							nodeSize += IndexEntryPtr->AttributeLength;
							dx++;
							IndexEntryPtr = (PINDEX_ENTRY)((SIZE_T)IndexEntryPtr + IndexEntryPtr->Length);
						}

						
					}
				}
			}


			Attribute = (PATTRIBUTE)((SIZE_T)Attribute + Attribute->Length);
		}

		// next record
		FileRecord = (PFILE_RECORD_HEADER)((SIZE_T)FileRecord + FileRecord->BytesAllocated);

	}

	end:
	CloseHandle(hFile);

}




int main(int argc, char** argv) {

	//
	if (argc == 0)
		ParseNtfsPartition("\\\\.\\HardDiskVolume1", 0);
	else
		ParseNtfsPartition(argv[1], 0);
	
	return 0;
}
