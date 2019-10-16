#include <Windows.h>
#include <stdio.h>

#ifdef _WIN64

typedef enum _RtlQueryHeapInformationClass {
	HeapCompatibilityInformation_redef = 0,
	HeapExtendedInformation = 2,
	HeapTags = 4,
	HeapStackTraceSerialize = 5,
	HeapFailureInfoPointer = 0x80000001
}RtlQueryHeapInformationClass;
#define HEAP_INFORMATION_MAX_LENGTH 0x58

typedef struct _RtlpQueryExtendedHeapInformationParameter {
	HANDLE		hProcess;								// + 0x00	: if INVALID_HANDLE_VALUE : current process
	HANDLE		heapHandle;								// + 0x08	: if NULL, all heaps will be queried
	ULONG		extendedInformationOutLength;			// + 0x10	: output
	ULONG		align4;									// + 0x14	: not used
	PVOID       pFctExtendedHeapInformationGenerator;	// + 0x18	: defaults to RtlpExtendedHeapInformationGenerator
	PBYTE		pExtendedHeapInformationOutputBuffer;	// + 0x20	: if pFctExtendedHeapInformationGenerator == NULL, defaults to the actual parameter
}RtlpQueryExtendedHeapInformationParameter, *pRtlpQueryExtendedHeapInformationParameter;
typedef struct _HEAP_UNPACKED_ENTRY
{
	/* 0x0000 */ void* PreviousBlockPrivateData;
	union
	{
		struct
		{
			/* 0x0008 */ unsigned short Size;
			/* 0x000a */ unsigned char Flags;
			/* 0x000b */ unsigned char SmallTagIndex;
		}; /* size: 0x0004 */
		struct
		{
			/* 0x0008 */ unsigned long SubSegmentCode;
			/* 0x000c */ unsigned short PreviousSize;
			union
			{
				/* 0x000e */ unsigned char SegmentOffset;
				struct
				{
					/* 0x000e */ unsigned char LFHFlags;
					/* 0x000f */ unsigned char UnusedBytes;
				}; /* size: 0x0002 */
			}; /* size: 0x0002 */
		}; /* size: 0x0008 */
		/* 0x0008 */ unsigned __int64 CompactHeader;
	}; /* size: 0x0008 */
} HEAP_UNPACKED_ENTRY, *PHEAP_UNPACKED_ENTRY; /* size: 0x0010 */

typedef struct _HEAP_EXTENDED_ENTRY
{
	/* 0x0000 */ void* Reserved;
	union
	{
		struct
		{
			/* 0x0008 */ unsigned short FunctionIndex;
			/* 0x000a */ unsigned short ContextValue;
		}; /* size: 0x0004 */
		/* 0x0008 */ unsigned long InterceptorValue;
	}; /* size: 0x0004 */
	/* 0x000c */ unsigned short UnusedBytesLength;
	/* 0x000e */ unsigned char EntryOffset;
	/* 0x000f */ unsigned char ExtendedBlockSignature;
} HEAP_EXTENDED_ENTRY, *PHEAP_EXTENDED_ENTRY; /* size: 0x0010 */

typedef struct _HEAP_ENTRY
{
	union
	{
		/* 0x0000 */ struct _HEAP_UNPACKED_ENTRY UnpackedEntry;
		struct
		{
			/* 0x0000 */ void* PreviousBlockPrivateData;
			union
			{
				struct
				{
					/* 0x0008 */ unsigned short Size;
					/* 0x000a */ unsigned char Flags;
					/* 0x000b */ unsigned char SmallTagIndex;
				}; /* size: 0x0004 */
				struct
				{
					/* 0x0008 */ unsigned long SubSegmentCode;
					/* 0x000c */ unsigned short PreviousSize;
					union
					{
						/* 0x000e */ unsigned char SegmentOffset;
						struct
						{
							/* 0x000e */ unsigned char LFHFlags;
							/* 0x000f */ unsigned char UnusedBytes;
						}; /* size: 0x0002 */
					}; /* size: 0x0002 */
				}; /* size: 0x0008 */
				/* 0x0008 */ unsigned __int64 CompactHeader;
			}; /* size: 0x0008 */
		}; /* size: 0x0010 */
		/* 0x0000 */ struct _HEAP_EXTENDED_ENTRY ExtendedEntry;
		struct
		{
			/* 0x0000 */ void* Reserved;
			union
			{
				struct
				{
					/* 0x0008 */ unsigned short FunctionIndex;
					/* 0x000a */ unsigned short ContextValue;
				}; /* size: 0x0004 */
				struct
				{
					/* 0x0008 */ unsigned long InterceptorValue;
					/* 0x000c */ unsigned short UnusedBytesLength;
					/* 0x000e */ unsigned char EntryOffset;
					/* 0x000f */ unsigned char ExtendedBlockSignature;
				}; /* size: 0x0008 */
			}; /* size: 0x0008 */
		}; /* size: 0x0010 */
		struct
		{
			/* 0x0000 */ void* ReservedForAlignment;
			union
			{
				struct
				{
					/* 0x0008 */ unsigned long Code1;
					union
					{
						struct
						{
							/* 0x000c */ unsigned short Code2;
							/* 0x000e */ unsigned char Code3;
							/* 0x000f */ unsigned char Code4;
						}; /* size: 0x0004 */
						/* 0x000c */ unsigned long Code234;
					}; /* size: 0x0004 */
				}; /* size: 0x0008 */
				/* 0x0008 */ unsigned __int64 AgregateCode;
			}; /* size: 0x0008 */
		}; /* size: 0x0010 */
	}; /* size: 0x0010 */
} HEAP_ENTRY, *PHEAP_ENTRY; /* size: 0x0010 */

typedef struct _HEAP_SEGMENT
{
	/* 0x0000 */ struct _HEAP_ENTRY Entry;
	/* 0x0010 */ unsigned long SegmentSignature;
	/* 0x0014 */ unsigned long SegmentFlags;
	/* 0x0018 */ struct _LIST_ENTRY SegmentListEntry;
	/* 0x0028 */ struct _HEAP* Heap;
	/* 0x0030 */ void* BaseAddress;
	/* 0x0038 */ unsigned long NumberOfPages;
	/* 0x0040 */ struct _HEAP_ENTRY* FirstEntry;
	/* 0x0048 */ struct _HEAP_ENTRY* LastValidEntry;
	/* 0x0050 */ unsigned long NumberOfUnCommittedPages;
	/* 0x0054 */ unsigned long NumberOfUnCommittedRanges;
	/* 0x0058 */ unsigned short SegmentAllocatorBackTraceIndex;
	/* 0x005a */ unsigned short Reserved;
	/* 0x0060 */ struct _LIST_ENTRY UCRSegmentList;
} HEAP_SEGMENT, *PHEAP_SEGMENT; /* size: 0x0070 */


typedef struct _RTL_HEAP_MEMORY_LIMIT_DATA
{
	/* 0x0000 */ unsigned __int64 CommitLimitBytes;
	/* 0x0008 */ unsigned __int64 CommitLimitFailureCode;
	/* 0x0010 */ unsigned __int64 MaxAllocationSizeBytes;
	/* 0x0018 */ unsigned __int64 AllocationLimitFailureCode;
} RTL_HEAP_MEMORY_LIMIT_DATA, *PRTL_HEAP_MEMORY_LIMIT_DATA; /* size: 0x0020 */

typedef struct _HEAP_COUNTERS
{
	/* 0x0000 */ unsigned __int64 TotalMemoryReserved;
	/* 0x0008 */ unsigned __int64 TotalMemoryCommitted;
	/* 0x0010 */ unsigned __int64 TotalMemoryLargeUCR;
	/* 0x0018 */ unsigned __int64 TotalSizeInVirtualBlocks;
	/* 0x0020 */ unsigned long TotalSegments;
	/* 0x0024 */ unsigned long TotalUCRs;
	/* 0x0028 */ unsigned long CommittOps;
	/* 0x002c */ unsigned long DeCommitOps;
	/* 0x0030 */ unsigned long LockAcquires;
	/* 0x0034 */ unsigned long LockCollisions;
	/* 0x0038 */ unsigned long CommitRate;
	/* 0x003c */ unsigned long DecommittRate;
	/* 0x0040 */ unsigned long CommitFailures;
	/* 0x0044 */ unsigned long InBlockCommitFailures;
	/* 0x0048 */ unsigned long PollIntervalCounter;
	/* 0x004c */ unsigned long DecommitsSinceLastCheck;
	/* 0x0050 */ unsigned long HeapPollInterval;
	/* 0x0054 */ unsigned long AllocAndFreeOps;
	/* 0x0058 */ unsigned long AllocationIndicesActive;
	/* 0x005c */ unsigned long InBlockDeccommits;
	/* 0x0060 */ unsigned __int64 InBlockDeccomitSize;
	/* 0x0068 */ unsigned __int64 HighWatermarkSize;
	/* 0x0070 */ unsigned __int64 LastPolledSize;
} HEAP_COUNTERS, *PHEAP_COUNTERS; /* size: 0x0078 */

typedef struct _HEAP_TUNING_PARAMETERS
{
	/* 0x0000 */ unsigned long CommittThresholdShift;
	/* 0x0008 */ unsigned __int64 MaxPreCommittThreshold;
} HEAP_TUNING_PARAMETERS, *PHEAP_TUNING_PARAMETERS; /* size: 0x0010 */

typedef struct _HEAP
{
	union
	{
		/* 0x0000 */ struct _HEAP_SEGMENT Segment;
		struct
		{
			/* 0x0000 */ struct _HEAP_ENTRY Entry;
			/* 0x0010 */ unsigned long SegmentSignature;
			/* 0x0014 */ unsigned long SegmentFlags;
			/* 0x0018 */ struct _LIST_ENTRY SegmentListEntry;
			/* 0x0028 */ struct _HEAP* Heap;
			/* 0x0030 */ void* BaseAddress;
			/* 0x0038 */ unsigned long NumberOfPages;
			/* 0x0040 */ struct _HEAP_ENTRY* FirstEntry;
			/* 0x0048 */ struct _HEAP_ENTRY* LastValidEntry;
			/* 0x0050 */ unsigned long NumberOfUnCommittedPages;
			/* 0x0054 */ unsigned long NumberOfUnCommittedRanges;
			/* 0x0058 */ unsigned short SegmentAllocatorBackTraceIndex;
			/* 0x005a */ unsigned short Reserved;
			/* 0x0060 */ struct _LIST_ENTRY UCRSegmentList;
		}; /* size: 0x0068 */
	}; /* size: 0x0070 */
	/* 0x0070 */ unsigned long Flags;
	/* 0x0074 */ unsigned long ForceFlags;
	/* 0x0078 */ unsigned long CompatibilityFlags;
	/* 0x007c */ unsigned long EncodeFlagMask;
	/* 0x0080 */ struct _HEAP_ENTRY Encoding;
	/* 0x0090 */ unsigned long Interceptor;
	/* 0x0094 */ unsigned long VirtualMemoryThreshold;
	/* 0x0098 */ unsigned long Signature;
	/* 0x00a0 */ unsigned __int64 SegmentReserve;
	/* 0x00a8 */ unsigned __int64 SegmentCommit;
	/* 0x00b0 */ unsigned __int64 DeCommitFreeBlockThreshold;
	/* 0x00b8 */ unsigned __int64 DeCommitTotalFreeThreshold;
	/* 0x00c0 */ unsigned __int64 TotalFreeSize;
	/* 0x00c8 */ unsigned __int64 MaximumAllocationSize;
	/* 0x00d0 */ unsigned short ProcessHeapsListIndex;
	/* 0x00d2 */ unsigned short HeaderValidateLength;
	/* 0x00d8 */ void* HeaderValidateCopy;
	/* 0x00e0 */ unsigned short NextAvailableTagIndex;
	/* 0x00e2 */ unsigned short MaximumTagIndex;
	/* 0x00e8 */ struct _HEAP_TAG_ENTRY* TagEntries;
	/* 0x00f0 */ struct _LIST_ENTRY UCRList;
	/* 0x0100 */ unsigned __int64 AlignRound;
	/* 0x0108 */ unsigned __int64 AlignMask;
	/* 0x0110 */ struct _LIST_ENTRY VirtualAllocdBlocks;
	/* 0x0120 */ struct _LIST_ENTRY SegmentList;
	/* 0x0130 */ unsigned short AllocatorBackTraceIndex;
	/* 0x0134 */ unsigned long NonDedicatedListLength;
	/* 0x0138 */ void* BlocksIndex;
	/* 0x0140 */ void* UCRIndex;
	/* 0x0148 */ struct _HEAP_PSEUDO_TAG_ENTRY* PseudoTagEntries;
	/* 0x0150 */ struct _LIST_ENTRY FreeLists;
	/* 0x0160 */ struct _HEAP_LOCK* LockVariable;
	/* 0x0168 */ void* CommitRoutine /* function */;
	/* 0x0170 */ union _RTL_RUN_ONCE StackTraceInitVar;
	/* 0x0178 */ struct _RTL_HEAP_MEMORY_LIMIT_DATA CommitLimitData;
	/* 0x0198 */ void* FrontEndHeap;
	/* 0x01a0 */ unsigned short FrontHeapLockCount;
	/* 0x01a2 */ unsigned char FrontEndHeapType;
	/* 0x01a3 */ unsigned char RequestedFrontEndHeapType;
	/* 0x01a8 */ wchar_t* FrontEndHeapUsageData;
	/* 0x01b0 */ unsigned short FrontEndHeapMaximumIndex;
	/* 0x01b2 */ volatile unsigned char FrontEndHeapStatusBitmap[129];
	/* 0x0238 */ struct _HEAP_COUNTERS Counters;
	/* 0x02b0 */ struct _HEAP_TUNING_PARAMETERS TuningParameters;
} HEAP, *PHEAP; /* size: 0x02c0 */

typedef struct _LIST_ENTRY_FU {
	struct _LIST_ENTRY_FU* Flink;
	struct _LIST_ENTRY_FU* Blink;
	PVOID dataPtr;
}LIST_ENTRY_FU, *PLIST_ENTRY_FU;

typedef struct _HEAP_UCR_DESCRIPTOR
{
	/* 0x0000 */ struct _LIST_ENTRY ListEntry;
	/* 0x0010 */ struct _LIST_ENTRY SegmentEntry;		// <--------------------------------------------- ignore it on segments
	/* 0x0020 */ void* Address;
	/* 0x0028 */ unsigned __int64 Size;
} HEAP_UCR_DESCRIPTOR, *PHEAP_UCR_DESCRIPTOR; /* size: 0x0030 */

typedef struct _HEAP_UCR_DESCRIPTOR_SEGMENT
{
	/* 0x0000 */ struct _LIST_ENTRY ListEntry;
	// /* 0x0010 */ struct _LIST_ENTRY SegmentEntry;		// <--------------------------------------------- ignore it on segments
	/* 0x0020 */ void* Address;
	/* 0x0028 */ unsigned __int64 Size;
} HEAP_UCR_DESCRIPTOR_SEGMENT, *PHEAP_UCR_DESCRIPTOR_SEGMENT; /* size: 0x0030 */

typedef struct _HEAP_ENTRY_EXTRA
{
	union
	{
		struct
		{
			/* 0x0000 */ unsigned short AllocatorBackTraceIndex;
			/* 0x0002 */ unsigned short TagIndex;
			/* 0x0008 */ unsigned __int64 Settable;
		}; /* size: 0x000c */
		struct
		{
			/* 0x0000 */ unsigned __int64 ZeroInit;
			/* 0x0008 */ unsigned __int64 ZeroInit1;
		}; /* size: 0x0010 */
	}; /* size: 0x0010 */
} HEAP_ENTRY_EXTRA, *PHEAP_ENTRY_EXTRA; /* size: 0x0010 */

typedef struct _HEAP_VIRTUAL_ALLOC_ENTRY
{
	/* 0x0000 */ struct _LIST_ENTRY Entry;
	/* 0x0010 */ struct _HEAP_ENTRY_EXTRA ExtraStuff;
	/* 0x0020 */ unsigned __int64 CommitSize;
	/* 0x0028 */ unsigned __int64 ReserveSize;
	/* 0x0030 */ struct _HEAP_ENTRY BusyBlock;
} HEAP_VIRTUAL_ALLOC_ENTRY, *PHEAP_VIRTUAL_ALLOC_ENTRY; /* size: 0x0040 */

typedef union _HEAP_BUCKET_RUN_INFO {
	ULONG Bucket;
	ULONG RunLength;
	LONG64 Aggregate64;
}HEAP_BUCKET_RUN_INFO, *PHEAP_BUCKET_RUN_INFO;

typedef union _HEAP_LFH_ONDEMAND_POINTER {
	USHORT Invalid : 1;
	USHORT AllocationInProgress : 1;
	USHORT Spare0 : 14;
	USHORT UsageData;
	PVOID AllBits;
}HEAP_LFH_ONDEMAND_POINTER, *PHEAP_LFH_ONDEMAND_POINTER;

typedef union _HEAP_LFH_SUBSEGMENT_DELAY_FREE {
	ULONG64 DelayFree : 1;
	ULONG64 Count : 63;
	PVOID AllBits;
}HEAP_LFH_SUBSEGMENT_DELAY_FREE, *PHEAP_LFH_SUBSEGMENT_DELAY_FREE;

typedef struct _HEAP_LFH_SUBSEGMENT_STAT {
	UCHAR Index;
	UCHAR Count;
}HEAP_LFH_SUBSEGMENT_STAT, *PHEAP_LFH_SUBSEGMENT_STAT;
typedef union _HEAP_LFH_SUBSEGMENT_STATS {
	struct _HEAP_LFH_SUBSEGMENT_STAT Buckets[4];
	PVOID AllStats;
}HEAP_LFH_SUBSEGMENT_STATS, *PHEAP_LFH_SUBSEGMENT_STATS;

typedef struct _LFH_BLOCK_ZONE {
	struct _LIST_ENTRY ListEntry;
	LONG NextIndex;
}LFH_BLOCK_ZONE, *PLFH_BLOCK_ZONE;

typedef union _HEAP_BUCKET_COUNTERS {
	ULONG TotalBlocks;
	ULONG SubSegmentCounts;
	LONG64 Aggregate64;
}HEAP_BUCKET_COUNTERS, *PHEAP_BUCKET_COUNTERS;
typedef struct _USER_MEMORY_CACHE_ENTRY {
	union _SLIST_HEADER UserBlocks;
	ULONG AvailableBlocks;
	ULONG MinimumDepth;
	ULONG CacheShiftThreshold;
	USHORT Allocations;
	USHORT Frees;
	USHORT CacheHits;
}USER_MEMORY_CACHE_ENTRY, *PUSER_MEMORY_CACHE_ENTRY;

typedef struct _HEAP_LFH_MEM_POLICIES {
	ULONG DisableAffinity : 1;
	ULONG SlowSubsegmentGrowth : 1;
	ULONG Spare : 30;
	ULONG AllPolicies;
}HEAP_LFH_MEM_POLICIES, *PHEAP_LFH_MEM_POLICIES;

typedef struct _HEAP_BUCKET {
	USHORT BlockUnits;
	UCHAR SizeIndex;
	UCHAR UseAffinity : 1;
	UCHAR DebugFlags : 2;
	UCHAR Flags;
}HEAP_BUCKET, *PHEAP_BUCKET;


typedef struct _HEAP_LOCAL_DATA {
	union _SLIST_HEADER DeletedSubSegments;
	struct _LFH_BLOCK_ZONE *CrtZone;
	struct _LFH_HEAP *LowFragHeap;
	ULONG Sequence;
	ULONG DeleteRateThreshold;
}HEAP_LOCAL_DATA, *PHEAP_LOCAL_DATA;

typedef struct _INTERLOCK_SEQ {
	USHORT Depth;
	USHORT Hint : 15;
	USHORT Lock : 1;
	USHORT Hint16;
	LONG Exchg;
}INTERLOCK_SEQ, *PINTERLOCK_SEQ;

typedef struct _RTL_BITMAP_EX {
	ULONG64 SizeOfBitMap;
	PULONG64 Buffer;
}RTL_BITMAP_EX, *PRTL_BITMAP_EX;

typedef struct _HEAP_USERDATA_OFFSETS {
	USHORT FirstAllocationOffset;
	USHORT BlockStride;
	ULONG StrideAndOffset;
}HEAP_USERDATA_OFFSETS, *PHEAP_USERDATA_OFFSETS;

typedef struct _HEAP_USERDATA_HEADER {
	struct _SINGLE_LIST_ENTRY SFreeListEntry;
	struct _HEAP_SUBSEGMENT *SubSegment;
	PVOID Reserved;
	ULONG SizeIndexAndPadding;
	UCHAR SizeIndex;
	UCHAR GuardPagePresent;
	USHORT PaddingBytes;
	ULONG Signature;
	struct _HEAP_USERDATA_OFFSETS EncodedOffsets;
	struct _RTL_BITMAP_EX BusyBitmap;
	ULONG64 BitmapData[1];
}HEAP_USERDATA_HEADER, *PHEAP_USERDATA_HEADER;

typedef struct _HEAP_LOCAL_SEGMENT_INFO {
	struct _HEAP_LOCAL_DATA *LocalData;
	struct _HEAP_SUBSEGMENT *ActiveSubsegment;
	struct _HEAP_SUBSEGMENT *CachedItems[16];
	union _SLIST_HEADER SListHeader;
	union _HEAP_BUCKET_COUNTERS Counters;
	ULONG LastOpSequence;
	USHORT BucketIndex;
	USHORT LastUsed;
	USHORT NoThrashCount;
}HEAP_LOCAL_SEGMENT_INFO, *PHEAP_LOCAL_SEGMENT_INFO;

typedef struct _HEAP_SUBSEGMENT {
	struct _HEAP_LOCAL_SEGMENT_INFO *LocalInfo;
	struct _HEAP_USERDATA_HEADER *UserBlocks;
	union _SLIST_HEADER DelayFreeList;
	struct _INTERLOCK_SEQ AggregateExchg;
	USHORT BlockSize;
	USHORT Flags;
	USHORT BlockCount;
	UCHAR SizeIndex;
	UCHAR AffinityIndex;
	ULONG Alignment[2];
	ULONG Lock;
	struct _SINGLE_LIST_ENTRY SFreeListEntry;
}HEAP_SUBSEGMENT, *PHEAP_SUBSEGMENT;

typedef struct _LFH_HEAP {
	struct _RTL_SRWLOCK Lock;
	struct _LIST_ENTRY SubSegmentZones;
	PVOID Heap;
	PVOID NextSegmentInfoArrayAddress;
	PVOID FirstUncommittedAddress;
	PVOID ReservedAddressLimit;
	ULONG SegmentCreate;
	ULONG SegmentDelete;
	ULONG MinimumCacheDepth;
	ULONG CacheShiftThreshold;
	ULONG64 SizeInCache;
	union _HEAP_BUCKET_RUN_INFO RunInfo;
	struct _USER_MEMORY_CACHE_ENTRY UserBlockCache[12];
	struct _HEAP_LFH_MEM_POLICIES MemoryPolicies;
	struct _HEAP_BUCKET Buckets[129];
	struct _HEAP_LOCAL_SEGMENT_INFO *SegmentInfoArrays[129];
	struct _HEAP_LOCAL_SEGMENT_INFO *AffinitizedInfoArrays[129];
	struct _SEGMENT_HEAP *SegmentAllocator;
	struct _HEAP_LOCAL_DATA LocalData[1];
}LFH_HEAP, *PLFH_HEAP;

typedef enum HeapFlags {
	HEAP_ENTRY_BUSY = 0x01,
	HEAP_ENTRY_EXTRA_PRESENT = 2,
	HEAP_ENTRY_FILL_PATTERN = 4,
	HEAP_ENTRY_VIRTUAL_ALLOC = 8,
	HEAP_ENTRY_LAST_ENTRY = 0x10
};
// --------------------------------- GLOBALS ---------------------------------------

PULONG Interceptor = NULL;

// --------------------------------- NT HEAP ---------------------------------------

BOOL isUncommittedAddress(PVOID address, PHEAP_SEGMENT CurrentSegment) {
	PHEAP_UCR_DESCRIPTOR_SEGMENT start, current;

	start = (PHEAP_UCR_DESCRIPTOR_SEGMENT)CurrentSegment->UCRSegmentList.Flink;
	current = start;
	while (current != (PHEAP_UCR_DESCRIPTOR_SEGMENT)&CurrentSegment->UCRSegmentList) {

		if (address >= current->Address && address <= (PVOID)((SIZE_T)current->Address + current->Size))
			return TRUE;
		current = (PHEAP_UCR_DESCRIPTOR_SEGMENT)current->ListEntry.Flink;
	} 

	return FALSE;
}

void WalkHeapEntries(PHEAP_ENTRY Start, PHEAP_ENTRY End, PHEAP_SEGMENT CurrentSegment) {
	PHEAP_ENTRY heapPtr = Start;
	ULONG DecodedSize, dataSize;
	HEAP_ENTRY decodedHeader;

	PBYTE pData = NULL;
	do {

		decodedHeader.InterceptorValue = heapPtr->InterceptorValue ^ *Interceptor;
		DecodedSize = decodedHeader.Size *sizeof(HEAP_ENTRY);

		printf("    |     |     |- Heap entry: %p\n", heapPtr);
		printf("    |     |     |     |- Block size: 0x%x (unused 0x%x)\n", DecodedSize, heapPtr->UnusedBytes);
		if ((decodedHeader.Flags & 0x3) == 0)
			printf("    |     |     |     |- FREE Block (Flags: 0x%x)\n", decodedHeader.Flags);
		else
			printf("    |     |     |     |- BUSY Block (Flags: 0x%x)\n", decodedHeader.Flags);

		printf("    |     |     |     |- SmallTagIndex: 0x%x\n", decodedHeader.SmallTagIndex);

		dataSize = DecodedSize - heapPtr->UnusedBytes;
		if (heapPtr->UnusedBytes == 0)
			dataSize -= sizeof(HEAP_ENTRY);
		printf("    |     |     |     |- Data size: 0x%x\n", dataSize);

		pData = (PBYTE)heapPtr + sizeof(HEAP_ENTRY);
		printf("    |     |     |     |- First data byte at %p : %.2x\n", pData, *pData);

		heapPtr = (PHEAP_ENTRY)((SIZE_T)heapPtr + DecodedSize);

		// last chunk of commited regions is a HEAP_UCR_DESCRIPTOR (size 0x40)
		if (DecodedSize == 0x40)
			while (isUncommittedAddress((PVOID)heapPtr, CurrentSegment))
				heapPtr = (PHEAP_ENTRY)(((SIZE_T)heapPtr + 0x1000) & ~0xFFF);

	} while (heapPtr < End);


}

void WalkBackEndSegmentList(PLIST_ENTRY_FU FirstListEntryPtr) {
	PLIST_ENTRY_FU CurrentSegmentEntry = NULL;
	PHEAP_SEGMENT heapSegment;

	CurrentSegmentEntry = FirstListEntryPtr;

	do {
		heapSegment = (PHEAP_SEGMENT)CurrentSegmentEntry->dataPtr;
		printf("    |- Segment: 0x%p\n", heapSegment);
		if (heapSegment != NULL) {
			printf("          |- Signature: 0x%x\n", heapSegment->SegmentSignature);
			printf("          |- SegmentFlags: 0x%x\n", heapSegment->SegmentFlags);
			printf("          |- NumberOfPages: 0x%x\n", heapSegment->NumberOfPages);
			printf("          |- FirstEntry: 0x%p\n", heapSegment->FirstEntry);
			printf("          |- LastValidEntry: 0x%p\n", heapSegment->LastValidEntry);
			printf("          |- NumberOfUnCommittedPages: 0x%x\n", heapSegment->NumberOfUnCommittedPages);
			if (heapSegment->SegmentListEntry.Flink != NULL)
				printf("          |- SegmentListEntry.Flink.DataPtr: 0x%p\n", ((PLIST_ENTRY_FU)(heapSegment->SegmentListEntry.Flink))->dataPtr);
			else
				printf("          |- SegmentListEntry.Flink: 0x%p\n", heapSegment->SegmentListEntry.Flink);
			printf("          |- LastValidEntry: 0x%p\n", heapSegment->LastValidEntry);
			if (heapSegment->FirstEntry != NULL)
				WalkHeapEntries(heapSegment->FirstEntry, heapSegment->LastValidEntry, heapSegment);
		}

		// we could also follow the heapSegment->SegmentListEntry above :)

		CurrentSegmentEntry = CurrentSegmentEntry->Flink;
	} while (CurrentSegmentEntry->dataPtr != FirstListEntryPtr->dataPtr);

}


void WalkVirtualAllocdBlocks(PHEAP_VIRTUAL_ALLOC_ENTRY FirstVAEntry) {
	PHEAP_VIRTUAL_ALLOC_ENTRY CurrentVAEntry;
	HEAP_ENTRY decodedHeader;
	SIZE_T blockSize = 0;
	PBYTE pData = NULL;

	CurrentVAEntry = FirstVAEntry;
	do {
		printf("    |- VirtualAllocated block : 0x%p\n", CurrentVAEntry);
		printf("          |- CommitSize : 0x%x\n", CurrentVAEntry->CommitSize);
		printf("          |- ReserveSize : 0x%x\n", CurrentVAEntry->ReserveSize);
		decodedHeader.InterceptorValue = *Interceptor ^ CurrentVAEntry->BusyBlock.InterceptorValue;
		blockSize = decodedHeader.Size * sizeof(HEAP_ENTRY);
		printf("          |- BusyBlock.Size : 0x%x\n", blockSize);
		if ((decodedHeader.Flags & 0x3) == 0)
			printf("          |- FREE Block (Flags: 0x%x)\n", decodedHeader.Flags);
		else
			printf("          |- BUSY Block (Flags: 0x%x)\n", decodedHeader.Flags);

		printf("          |- SmallTagIndex: 0x%x\n", decodedHeader.SmallTagIndex);

		if (CurrentVAEntry->CommitSize != 0) {
			printf("          |- Data size : 0x%x\n", blockSize - sizeof(HEAP_VIRTUAL_ALLOC_ENTRY));
			pData = (PBYTE)CurrentVAEntry + sizeof(HEAP_VIRTUAL_ALLOC_ENTRY);
			printf("          |- First data byte at %p : %.2x\n", pData, *pData);
		}

		CurrentVAEntry = (PHEAP_VIRTUAL_ALLOC_ENTRY)CurrentVAEntry->Entry.Flink;
	} while (CurrentVAEntry != FirstVAEntry);
}


void allocHeap(ULONG size, HANDLE hHeap, UCHAR c) {
	PVOID x;
	x = HeapAlloc(hHeap, 0, size);
	memset(x, c, size);
	printf("    |- Allocated %x bytes with %c pattern at %p\n", size, c, x);
}

#define LFH_TRIGGER_SIZE 0x1000
void doAllocations(HANDLE hHeap) {
	ULONG cpt;
	PVOID items[LFH_TRIGGER_SIZE];

	// small allocations
	for (cpt = 0; cpt < LFH_TRIGGER_SIZE; cpt++)
		items[cpt] = HeapAlloc(hHeap, 0, 0x20);
	for (cpt = 0; cpt < LFH_TRIGGER_SIZE; cpt += 2)
		HeapFree(hHeap, 0, items[cpt]);

	for (cpt = 0; cpt < LFH_TRIGGER_SIZE; cpt++)
		items[cpt] = HeapAlloc(hHeap, 0, 0x40);
	for (cpt = 0; cpt < LFH_TRIGGER_SIZE; cpt += 2)
		HeapFree(hHeap, 0, items[cpt]);

	for (cpt = 0; cpt < LFH_TRIGGER_SIZE; cpt++)
		items[cpt] = HeapAlloc(hHeap, 0, 0x50);
	for (cpt = 0; cpt < LFH_TRIGGER_SIZE; cpt++)
		items[cpt] = HeapAlloc(hHeap, 0, 0x10);
	for (cpt = 0; cpt < LFH_TRIGGER_SIZE; cpt++)
		items[cpt] = HeapAlloc(hHeap, 0, 0x5);
	for (cpt = 0; cpt < LFH_TRIGGER_SIZE; cpt++)
		items[cpt] = HeapAlloc(hHeap, 0, 0x500);

	allocHeap(0x100, hHeap, 0x42);
	allocHeap(0x1000, hHeap, 0x43);
	allocHeap(0x10001, hHeap, 0x44);
	allocHeap(0x20, hHeap, 0x45);
	allocHeap(0x200, hHeap, 0x46);

	// small allocation + free
	PVOID x = HeapAlloc(hHeap, 0, 0xf0f0);
	memset(x, 0xCC, 0xf0f0);
	HeapFree(hHeap, 0, x);
	printf("    |- Allocated %x bytes with 0xCC pattern at %p\n", 0xf0f0, x);

	// large allocations
	allocHeap(((PHEAP)hHeap)->VirtualMemoryThreshold * sizeof(HEAP_ENTRY) + 0x10, hHeap, 0x47);
	allocHeap(((PHEAP)hHeap)->VirtualMemoryThreshold * sizeof(HEAP_ENTRY) * 2, hHeap, 0x48);

}

void WalkLFHSubSegment(PHEAP_SUBSEGMENT SubSegment) {
	PHEAP_ENTRY EntriesPtr = NULL;
	printf("    |    |    |     |- BlockSize: 0x%x\n", SubSegment->BlockSize);
	printf("    |    |    |     |- Flags: 0x%x\n", SubSegment->Flags);
	printf("    |    |    |     |- BlockCount: 0x%x\n", SubSegment->BlockCount);
	printf("    |    |    |     |- SizeIndex: 0x%x\n", SubSegment->SizeIndex);
	printf("    |    |    |     |- AffinityIndex: 0x%x\n", SubSegment->AffinityIndex);
	printf("    |    |    |     |- AggregateExchg.Depth (free chunks left): 0x%x\n", SubSegment->AggregateExchg.Depth);
	printf("    |    |    |     |- AggregateExchg.Hint16: 0x%x\n", SubSegment->AggregateExchg.Hint16);
	printf("    |    |    |     |- AggregateExchg.Exchg: 0x%x\n", SubSegment->AggregateExchg.Exchg);
	printf("    |    |    |     |- LocalInfo: 0x%p\n", SubSegment->LocalInfo);
	printf("    |    |    |     |- UserBlocks: 0x%p\n", SubSegment->UserBlocks);
	if (SubSegment->UserBlocks != NULL) {
		printf("    |    |    |     |    |- GuardPagePresent: 0x%x\n", SubSegment->UserBlocks->GuardPagePresent);
		printf("    |    |    |     |    |- Signature: 0x%x\n", SubSegment->UserBlocks->Signature);
		printf("    |    |    |     |    |- SizeIndex: 0x%x\n", SubSegment->UserBlocks->SizeIndex);
		printf("    |    |    |     |    |- EncodedOffsets: 0x%x\n", SubSegment->UserBlocks->EncodedOffsets);
		printf("    |    |    |     |    |- SFreeListEntry: 0x%p\n", SubSegment->UserBlocks->SFreeListEntry.Next);
		printf("    |    |    |     |    |- BusyBitmap.Buffer : 0x%p\n", SubSegment->UserBlocks->BusyBitmap.Buffer);
		printf("    |    |    |     |    |- BusyBitmap.SizeOfBitMap : 0x%x\n", SubSegment->UserBlocks->BusyBitmap.SizeOfBitMap);

		EntriesPtr = (PHEAP_ENTRY)((SIZE_T)&SubSegment->UserBlocks + sizeof(HEAP_USERDATA_HEADER));
		printf("    |    |    |     |    |- Data pointer: 0x%p\n", EntriesPtr);

		for (ULONG i = 0; i < 0x100; i++) {
			if (i % 0x10 == 0)
				printf("\n\t");
			printf("%.2X ", ((PBYTE)EntriesPtr)[i]);

		}
		printf("\n");
	}


}


void WalkLFHHeap(PLFH_HEAP LfhHeap) {
	PHEAP_LOCAL_DATA* LocalDataPtr = NULL;
	PHEAP_LOCAL_SEGMENT_INFO LocalSegmentInfoPtr = NULL;
	ULONG i = 0;
	PLIST_ENTRY ListEntryPtr;

	printf("LFH Heap parsing\n");
	printf("    |- Heap: 0x%p\n", LfhHeap->Heap);
	printf("    |- SegmentAllocator: 0x%p\n", LfhHeap->SegmentAllocator);
	printf("    |- NextSegmentInfoArrayAddress: 0x%p\n", LfhHeap->NextSegmentInfoArrayAddress);
	printf("    |- FirstUncommittedAddress: 0x%p\n", LfhHeap->FirstUncommittedAddress);

	printf("    |- SubSegmentZones:\n");
	ListEntryPtr = LfhHeap->SubSegmentZones.Flink;
	do {
		printf("    |     |- NextIndex: 0x%x\n", ((PLFH_BLOCK_ZONE)ListEntryPtr)->NextIndex);

	} while (ListEntryPtr != LfhHeap->SubSegmentZones.Flink);

	printf("    |- ReservedAddressLimit: 0x%p\n", LfhHeap->ReservedAddressLimit);
	printf("    |- SegmentCreate: 0x%x\n", LfhHeap->SegmentCreate);
	printf("    |- SegmentDelete: 0x%x\n", LfhHeap->SegmentDelete);
	printf("    |- MinimumCacheDepth: 0x%x\n", LfhHeap->MinimumCacheDepth);
	printf("    |- CacheShiftThreshold: 0x%x\n", LfhHeap->CacheShiftThreshold);
	printf("    |- SizeInCache: 0x%x\n", LfhHeap->SizeInCache);
	printf("    |- RunInfo.Aggregate64: 0x%x\n", LfhHeap->RunInfo.Aggregate64);
	printf("    |- MemoryPolicies.AllPolicies: 0x%x\n", LfhHeap->MemoryPolicies.AllPolicies);
	printf("    |- Buckets (non-zero BlockUnits):\n");
	for (i = 0; i< 128; i++) {
		if (LfhHeap->Buckets[i].BlockUnits != 0) {
			printf("    |    |- Bucket %x : Block Units %x/Debug Flags %x/Flags %x/SizeIndex %x/UseAffinity %x\n",
			i,
			LfhHeap->Buckets[i].BlockUnits,
			LfhHeap->Buckets[i].DebugFlags,
			LfhHeap->Buckets[i].Flags,
			LfhHeap->Buckets[i].SizeIndex,
			LfhHeap->Buckets[i].UseAffinity);
		}
	}

	printf("    |- UserBlockCache\n");
	for (i = 0; i<12; i++) {
		printf("    |    |- Item %x\n", i);
		printf("    |    |     |- Allocations: 0x%x\n", LfhHeap->UserBlockCache[i].Allocations);
		printf("    |    |     |- AvailableBlocks: 0x%x\n", LfhHeap->UserBlockCache[i].AvailableBlocks);
		printf("    |    |     |- MinimumDepth: 0x%x\n", LfhHeap->UserBlockCache[i].MinimumDepth);
		printf("    |    |     |- CacheShiftThreshold: 0x%x\n", LfhHeap->UserBlockCache[i].CacheShiftThreshold);
		printf("    |    |     |- Frees: 0x%x\n", LfhHeap->UserBlockCache[i].Frees);
		printf("    |    |     |- CacheHits: 0x%x\n", LfhHeap->UserBlockCache[i].CacheHits);
		printf("    |    |     |- UserBlocks.HeaderX64: 0x%x\n", LfhHeap->UserBlockCache[i].UserBlocks.HeaderX64);

	}

	LocalDataPtr = (PHEAP_LOCAL_DATA*) &LfhHeap->LocalData;
	while (*LocalDataPtr != NULL && *LocalDataPtr > (PVOID)0x0000001400000FFF) {
		printf("    |-  LocalData 0x%p\n", *LocalDataPtr);
		printf("    |    |- CrtZone: 0x%p\n", (*LocalDataPtr)->CrtZone);
		printf("    |    |- Sequence: 0x%x\n", (*LocalDataPtr)->Sequence);
		LocalDataPtr++;
	}

	printf("    |- Non-null SegmentInfoArrays:\n");
	for (i = 0; i < 128; i++) {
		LocalSegmentInfoPtr = LfhHeap->SegmentInfoArrays[i];
		if (LocalSegmentInfoPtr != NULL) {
			printf("    |    |- SubSegment 0x%x\n", i);
			printf("    |    |    |- Pointer: 0x%p\n", LocalSegmentInfoPtr);

			if (LocalSegmentInfoPtr >(PVOID)0x0000001400000FFF) {

				printf("    |    |    |- ActiveSubSegment: 0x%p\n", LocalSegmentInfoPtr->ActiveSubsegment);
				if (LocalSegmentInfoPtr->ActiveSubsegment != NULL) {
					WalkLFHSubSegment(LocalSegmentInfoPtr->ActiveSubsegment);
				}
				printf("    |    |    |- LocalData: 0x%p\n", LocalSegmentInfoPtr->LocalData);
				printf("    |    |    |- LastUsed: 0x%x\n", LocalSegmentInfoPtr->LastUsed);
				printf("    |    |    |- Counters: 0x%x\n", LocalSegmentInfoPtr->Counters.Aggregate64);
				printf("    |    |    |- BucketIndex: 0x%x\n", LocalSegmentInfoPtr->BucketIndex);
				for (ULONG j = 0; j < 16; j++) {
					printf("    |    |    |- CachedItems[%d]: 0x%p\n", j, LocalSegmentInfoPtr->CachedItems[j]);
					if (LocalSegmentInfoPtr->CachedItems[j] != NULL)
						WalkLFHSubSegment(LocalSegmentInfoPtr->CachedItems[j]);
				}
			}

		}
	}

	printf("    |- Non-null AffinitizedInfoArrays:\n");
	for (i = 0; i < 128; i++) {
		LocalSegmentInfoPtr = LfhHeap->AffinitizedInfoArrays[i];
		if (LocalSegmentInfoPtr != NULL) {
			printf("    |    |- SubSegment 0x%x\n", i);
			printf("    |    |    |- Pointer: 0x%p\n", LocalSegmentInfoPtr);
			if (LocalSegmentInfoPtr >(PVOID)0x0000001400000FFF) {
				printf("    |    |    |- ActiveSubSegment: 0x%p\n", LocalSegmentInfoPtr->ActiveSubsegment);
				if (LocalSegmentInfoPtr->ActiveSubsegment != NULL) {
					WalkLFHSubSegment(LocalSegmentInfoPtr->ActiveSubsegment);
				}
				printf("    |    |    |- LocalData: 0x%p\n", LocalSegmentInfoPtr->LocalData);
				printf("    |    |    |- Counters: 0x%x\n", LocalSegmentInfoPtr->Counters.Aggregate64);
			}
		}
	}


}

void WalkNTHeap(PHEAP heapPointer) {

	printf("NT Heap parsing\n");

	printf("Heap signature: 0x%x\n", heapPointer->SegmentSignature);
	printf("Heap VirtualMemoryThreshold: 0x%x\n", heapPointer->VirtualMemoryThreshold* sizeof(HEAP_ENTRY));

	Interceptor = (PULONG)((PBYTE)heapPointer + 0x88);
	printf("Heap Interceptor: 0x%x\n", *Interceptor);

	printf("Walking BackEnd :\n");
	WalkBackEndSegmentList((PLIST_ENTRY_FU)(heapPointer->SegmentList.Flink));

	printf("Walking VirtualAllocdBlocks:\n");
	WalkVirtualAllocdBlocks((PHEAP_VIRTUAL_ALLOC_ENTRY)heapPointer->VirtualAllocdBlocks.Flink);

	if (heapPointer->FrontEndHeapType == 0)
		printf("FrontEnd heap is BACKEND HEAP\n");
	else if (heapPointer->FrontEndHeapType == 1)
		printf("FrontEnd heap is LOOKASIDE LISTS\n");
	else if (heapPointer->FrontEndHeapType == 2) {
		printf("FrontEnd heap is LOW FRAGMENTATION HEAP\n");
		printf("FrontEndHeap: 0x%p\n", heapPointer->FrontEndHeap);
		WalkLFHHeap((PLFH_HEAP)heapPointer->FrontEndHeap);
	}
	
	printf("\n");


}

void walkHeap(HANDLE hHeap) {
	BYTE heapInformation[HEAP_INFORMATION_MAX_LENGTH];
	SIZE_T dwLength, i;
	pRtlpQueryExtendedHeapInformationParameter extendedHeapInfo;
	PHEAP heapPointer;
	printf("HEAP ADDRESS = 0x%p\n", hHeap);

	HeapQueryInformation(hHeap,
		(HEAP_INFORMATION_CLASS)HeapCompatibilityInformation_redef,
		heapInformation,
		HEAP_INFORMATION_MAX_LENGTH,
		&dwLength);
	printf("HeapCompatibilityInformation = 0x%x\n", *(PULONG)heapInformation);

	HeapQueryInformation(hHeap,
		(HEAP_INFORMATION_CLASS)HeapFailureInfoPointer,
		heapInformation,
		HEAP_INFORMATION_MAX_LENGTH,
		&dwLength);
	printf("HeapFailureInfoPointer = 0x%p\n", *(PVOID*)heapInformation);

	memset(heapInformation, 0x00, HEAP_INFORMATION_MAX_LENGTH);
	extendedHeapInfo = (pRtlpQueryExtendedHeapInformationParameter)heapInformation;
	extendedHeapInfo->heapHandle = hHeap;
	extendedHeapInfo->hProcess = INVALID_HANDLE_VALUE;
	extendedHeapInfo->pFctExtendedHeapInformationGenerator = NULL;
	extendedHeapInfo->extendedInformationOutLength = 0;
	extendedHeapInfo->pExtendedHeapInformationOutputBuffer = NULL;

	HeapQueryInformation(hHeap,
		(HEAP_INFORMATION_CLASS)HeapExtendedInformation,
		heapInformation,
		HEAP_INFORMATION_MAX_LENGTH,
		&dwLength);
	printf("Extended heap information (%d):", GetLastError());
	for (i = 0; i < dwLength; i++) {
		if (i % 0x10 == 0)
			printf("\n\t");
		printf("%.2X ", heapInformation[i]);

	}
	printf("\n");

	heapPointer = (PHEAP)hHeap;
	if (heapPointer->Signature == 0xEEFFEEFF)
		WalkNTHeap(heapPointer);

}

int main(int argc, char** argv) {
	HANDLE hHeap = NULL;
	ULONG dummy = 2;
	/*
	ULONG i = 0;
	HANDLE hHeaps[0x100];
	for (i = 0; i < GetProcessHeaps(0x100, hHeaps); i++) {

		printf("========== DEFAULT PROCESS HEAP #%d ==========\n", i);
		walkHeap(hHeaps[i]);
		
	}
	*/

	printf("========== LFH HEAP ==========\n");
	hHeap = HeapCreate(0, 0, 0);
	HeapLock(hHeap);
	if (HeapSetInformation(hHeap, HeapCompatibilityInformation, &dummy, sizeof(ULONG)) == FALSE) {
		HeapUnlock(hHeap);
		printf("[!] Cannot enable LFH : 0x%x\n", GetLastError());
	}
	else {
		HeapUnlock(hHeap);
	

		printf("allocating stuff...\n");
		doAllocations(hHeap);

		walkHeap(hHeap);
	}
	system("pause");
	return(0);
}

#endif;
