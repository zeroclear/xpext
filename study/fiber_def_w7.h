
#define WIN32_NO_STATUS
#include <Windows.h>
#undef WIN32_NO_STATUS
#include <ntstatus.h>

#pragma comment(lib,"E:\\WDK\\lib\\win7\\i386\\ntdll.lib")

typedef struct _UNICODE_STRING {
	USHORT  Length;
	USHORT  MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _FLS_CALLBACK_INFO
{
	PFLS_CALLBACK_FUNCTION CallbackFunc;
	RTL_SRWLOCK FlsCbLock;
} FLS_CALLBACK_INFO;

typedef struct _RTL_BITMAP {
	ULONG SizeOfBitmap;
	PULONG Buffer;
} RTL_BITMAP, *PRTL_BITMAP;

typedef struct _PEB
{
	UCHAR InheritedAddressSpace;	//+0x000
	UCHAR ReadImageFileExecOptions;	//+0x001
	UCHAR BeingDebugged;	//+0x002

	union
	{
		UCHAR BitField;	//+0x003
		struct
		{
			UCHAR ImageUsesLargePages:1;
			UCHAR IsProtectedProcess:1;
			UCHAR IsLegacyProcess:1;
			UCHAR IsImageDynamicallyRelocated:1;
			UCHAR SkipPatchingUser32Forwarders:1;
			UCHAR SpareBits:3;
		};
	};

	PVOID Mutant;	//+0x004
	PVOID ImageBaseAddress;	//+0x008
	PVOID Ldr;	//+0x00c PEB_LDR_DATA*
	PVOID ProcessParameters;	//+0x010 RTL_USER_PROCESS_PARAMETERS*
	PVOID SubSystemData;	//+0x014
	PVOID ProcessHeap;	//+0x018
	RTL_CRITICAL_SECTION* FastPebLock;	//+0x01c
	PVOID AtlThunkSListPtr;	//+0x020
	PVOID IFEOKey;	//+0x024

	union
	{
		ULONG CrossProcessFlags;	//+0x028
		struct
		{
			ULONG ProcessInJob:1;	//+0x028
			ULONG ProcessInitializing:1;	//+0x028
			ULONG ProcessUsingVEH:1;	//+0x028
			ULONG ProcessUsingVCH:1;	//+0x028
			ULONG ProcessUsingFTH:1;	//+0x028
			ULONG ReservedBits0:27;	//+0x028
		};
	};

	PVOID KernelCallbackTable;	//+0x02c
	PVOID UserSharedInfoPtr;	//+0x02c
	ULONG SystemReserved[1];	//+0x030
	ULONG AtlThunkSListPtr32;	//+0x034
	PVOID ApiSetMap;	//+0x038
	ULONG TlsExpansionCounter;	//+0x03c
	PVOID TlsBitmap;	//+0x040
	ULONG TlsBitmapBits[2];	//+0x044
	PVOID ReadOnlySharedMemoryBase;	//+0x04c
	PVOID HotpatchInformation;	//+0x050
	PVOID* ReadOnlyStaticServerData;	//+0x054
	PVOID AnsiCodePageData;	//+0x058
	PVOID OemCodePageData;	//+0x05c
	PVOID UnicodeCaseTableData;	//+0x060
	ULONG NumberOfProcessors;	//+0x064
	ULONG NtGlobalFlag;	//+0x068
	LARGE_INTEGER CriticalSectionTimeout;	//+0x070
	ULONG HeapSegmentReserve;	//+0x078
	ULONG HeapSegmentCommit;	//+0x07c
	ULONG HeapDeCommitTotalFreeThreshold;	//+0x080
	ULONG HeapDeCommitFreeBlockThreshold;	//+0x084
	ULONG NumberOfHeaps;	//+0x088
	ULONG MaximumNumberOfHeaps;	//+0x08c
	PVOID* ProcessHeaps;	//+0x090
	PVOID GdiSharedHandleTable;	//+0x094
	PVOID ProcessStarterHelper;	//+0x098
	ULONG GdiDCAttributeList;	//+0x09c
	RTL_CRITICAL_SECTION* LoaderLock;	//+0x0a0
	ULONG OSMajorVersion;	//+0x0a4
	ULONG OSMinorVersion;	//+0x0a8
	USHORT OSBuildNumber;	//+0x0ac
	USHORT OSCSDVersion;	//+0x0ae
	ULONG OSPlatformId;	//+0x0b0
	ULONG ImageSubsystem;	//+0x0b4
	ULONG ImageSubsystemMajorVersion;	//+0x0b8
	ULONG ImageSubsystemMinorVersion;	//+0x0bc
	ULONG ActiveProcessAffinityMask;	//+0x0c0
	ULONG GdiHandleBuffer[34];	//+0x0c4
	PVOID PostProcessInitRoutine;	//+0x14c
	PVOID TlsExpansionBitmap;	//+0x150
	ULONG TlsExpansionBitmapBits[32];	//+0x154
	ULONG SessionId;	//+0x1d4
	ULARGE_INTEGER AppCompatFlags;	//+0x1d8
	ULARGE_INTEGER AppCompatFlagsUser;	//+0x1e0
	PVOID pShimData;	//+0x1e8
	PVOID AppCompatInfo;	//+0x1ec
	UNICODE_STRING CSDVersion;	//+0x1f0
	PVOID ActivationContextData;	//+0x1f8 ACTIVATION_CONTEXT_DATA*
	PVOID ProcessAssemblyStorageMap;	//+0x1fc ASSEMBLY_STORAGE_MAP*
	PVOID SystemDefaultActivationContextData;	//+0x200 ACTIVATION_CONTEXT_DATA*
	PVOID SystemAssemblyStorageMap;	//+0x204 ASSEMBLY_STORAGE_MAP*
	ULONG MinimumStackCommit;	//+0x208
	FLS_CALLBACK_INFO* FlsCallback;	//+0x20c
	LIST_ENTRY FlsListHead;	//+0x210
	RTL_BITMAP* FlsBitmap;	//+0x218
	ULONG FlsBitmapBits[4];	//+0x21c
	ULONG FlsHighIndex;	//+0x22c
	PVOID WerRegistrationData;	//+0x230
	PVOID WerShipAssertPtr;	//+0x234
	PVOID pContextData;	//+0x238
	PVOID pImageHeaderHash;	//+0x23c

	union
	{
		ULONG TracingFlags;	//+0x240
		struct
		{
			ULONG HeapTracingEnabled:1;	//+0x240
			ULONG CritSecTracingEnabled:1;	//+0x240
			ULONG SpareTracingBits:30;	//+0x240
		};
	};
} PEB;

typedef struct _CLIENT_ID {
	HANDLE UniqueProcess;
	HANDLE UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

typedef struct _RTL_ACTIVATION_CONTEXT_STACK_FRAME
{
	_RTL_ACTIVATION_CONTEXT_STACK_FRAME* Previous;
	PVOID ActivationContext;	//ACTIVATION_CONTEXT*
	ULONG Flags;
} RTL_ACTIVATION_CONTEXT_STACK_FRAME;

typedef struct _ACTIVATION_CONTEXT_STACK
{
	RTL_ACTIVATION_CONTEXT_STACK_FRAME* ActiveFrame;
	LIST_ENTRY FrameListCache;
	ULONG Flags;
	ULONG NextCookieSequenceNumber;
	ULONG StackId;
} ACTIVATION_CONTEXT_STACK;

typedef struct _GDI_TEB_BATCH
{
	ULONG Offset;
	ULONG hDC;
	ULONG Buffer[310];
} GDI_TEB_BATCH;

typedef struct _TEB
{
	NT_TIB NtTib;	//+0x000
	PVOID EnvironmentPointer;	//+0x01c
	CLIENT_ID ClientId;	//+0x020
	PVOID ActiveRpcHandle;	//+0x028
	PVOID ThreadLocalStoragePointer;	//+0x02c
	PEB* ProcessEnvironmentBlock;	//+0x030
	ULONG LastErrorValue;	//+0x034
	ULONG CountOfOwnedCriticalSections;	//+0x038
	PVOID CsrClientThread;	//+0x03c
	PVOID Win32ThreadInfo;	//+0x040
	ULONG User32Reserved[26];	//+0x044
	ULONG UserReserved[5];	//+0x0ac
	PVOID WOW32Reserved;	//+0x0c0
	ULONG CurrentLocale;	//+0x0c4
	ULONG FpSoftwareStatusRegister;	//+0x0c8
	PVOID SystemReserved1[54];	//+0x0cc
	LONG ExceptionCode;	//+0x1a4
	ACTIVATION_CONTEXT_STACK* ActivationContextStackPointer;	//+0x1a8
	UCHAR SpareBytes[36];	//+0x1ac
	ULONG TxFsContext;	//+0x1d0
	GDI_TEB_BATCH GdiTebBatch;	//+0x1d4
	_CLIENT_ID RealClientId;	//+0x6b4
	PVOID GdiCachedProcessHandle;	//+0x6bc
	ULONG GdiClientPID;	//+0x6c0
	ULONG GdiClientTID;	//+0x6c4
	PVOID GdiThreadLocalInfo;	//+0x6c8
	ULONG Win32ClientInfo[62];	//+0x6cc
	PVOID glDispatchTable[233];	//+0x7c4
	ULONG glReserved1[29];	//+0xb68
	PVOID glReserved2;	//+0xbdc
	PVOID glSectionInfo;	//+0xbe0
	PVOID glSection;	//+0xbe4
	PVOID glTable;	//+0xbe8
	PVOID glCurrentRC;	//+0xbec
	PVOID glContext;	//+0xbf0
	ULONG LastStatusValue;	//+0xbf4
	UNICODE_STRING StaticUnicodeString;	//+0xbf8
	WCHAR StaticUnicodeBuffer[261];	//+0xc00
	PVOID DeallocationStack;	//+0xe0c
	PVOID TlsSlots[64];	//+0xe10
	LIST_ENTRY TlsLinks;	//+0xf10
	PVOID Vdm;	//+0xf18
	PVOID ReservedForNtRpc;	//+0xf1c
	PVOID DbgSsReserved[2];	//+0xf20
	ULONG HardErrorMode;	//+0xf28
	PVOID Instrumentation[9];	//+0xf2c
	GUID ActivityId;	//+0xf50
	PVOID SubProcessTag;	//+0xf60
	PVOID EtwLocalData;	//+0xf64
	PVOID EtwTraceData;	//+0xf68
	PVOID WinSockData;	//+0xf6c
	ULONG GdiBatchCount;	//+0xf70
	PROCESSOR_NUMBER CurrentIdealProcessor;	//+0xf74
	ULONG IdealProcessorValue;	//+0xf74
	UCHAR ReservedPad0;	//+0xf74
	UCHAR ReservedPad1;	//+0xf75
	UCHAR ReservedPad2;	//+0xf76
	UCHAR IdealProcessor;	//+0xf77
	ULONG GuaranteedStackBytes;	//+0xf78
	PVOID ReservedForPerf;	//+0xf7c
	PVOID ReservedForOle;	//+0xf80
	ULONG WaitingOnLoaderLock;	//+0xf84
	PVOID SavedPriorityState;	//+0xf88
	ULONG SoftPatchPtr1;	//+0xf8c
	PVOID ThreadPoolData;	//+0xf90
	PVOID* TlsExpansionSlots;	//+0xf94
	ULONG MuiGeneration;	//+0xf98
	ULONG IsImpersonating;	//+0xf9c
	PVOID NlsCache;	//+0xfa0
	PVOID pShimData;	//+0xfa4
	ULONG HeapVirtualAffinity;	//+0xfa8
	PVOID CurrentTransactionHandle;	//+0xfac
	PVOID ActiveFrame;	//+0xfb0 TEB_ACTIVE_FRAME*
	PVOID FlsData;	//+0xfb4
	PVOID PreferredLanguages;	//+0xfb8
	PVOID UserPrefLanguages;	//+0xfbc
	PVOID MergedPrefLanguages;	//+0xfc0
	ULONG MuiImpersonation;	//+0xfc4

	union
	{
		USHORT CrossTebFlags;	//+0xfc8
		struct
		{
			USHORT SpareCrossTebBits:16;
		};
	};

	union
	{
		USHORT SameTebFlags;	//+0xfca
		struct
		{
			USHORT SafeThunkCall:1;	//XP Teb+0xFB4
			USHORT InDebugPrint:1;
			USHORT HasFiberData:1;	//XP Teb+0xF76
			USHORT SkipThreadAttach:1;
			USHORT WerInShipAssertCode:1;
			USHORT RanProcessInit:1;
			USHORT ClonedThread:1;
			USHORT SuppressDebugMsg:1;
			USHORT DisableUserStackWalk:1;
			USHORT RtlExceptionAttached:1;
			USHORT InitialThread:1;
			USHORT SpareSameTebBits:5;
		};
	};

	PVOID TxnScopeEnterCallback;	//+0xfcc
	PVOID TxnScopeExitCallback;	//+0xfd0
	PVOID TxnScopeContext;	//+0xfd4
	ULONG LockCount;	//+0xfd8
	ULONG SpareUlong0;	//+0xfdc
	PVOID ResourceRetValue;	//+0xfe0
} TEB;

typedef struct _INITIAL_TEB {
	struct
	{
		PVOID OldStackBase;
		PVOID OldStackLimit;
	} OldInitialTeb;
	PVOID StackBase;
	PVOID StackLimit;
	PVOID StackAllocationBase;
} INITIAL_TEB, *PINITIAL_TEB;

typedef enum _PROCESSINFOCLASS {
	ProcessThreadStackAllocation = 41,
} PROCESSINFOCLASS;

typedef struct _PROCESS_STACK_ALLOCATION_INFORMATION
{
	ULONG ReserveSize;
	ULONG ZeroBits;
	PVOID StackBase;
} PROCESS_STACK_ALLOCATION_INFORMATION;

typedef struct _PROCESS_STACK_ALLOCATION_INFORMATION_EX
{
	ULONG ExtraType;
	ULONG Zero1;
	ULONG Zero2;
	ULONG Zero3;
	PROCESS_STACK_ALLOCATION_INFORMATION AllocInfo;
} PROCESS_STACK_ALLOCATION_INFORMATION_EX;

typedef struct _SYSTEM_BASIC_INFORMATION {
	ULONG Reserved;
	ULONG TimerResolution;
	ULONG PageSize;
	ULONG NumberOfPhysicalPages;
	ULONG LowestPhysicalPageNumber;
	ULONG HighestPhysicalPageNumber;
	ULONG AllocationGranularity;
	ULONG_PTR MinimumUserModeAddress;
	ULONG_PTR MaximumUserModeAddress;
	ULONG_PTR ActiveProcessorsAffinityMask;
	CCHAR NumberOfProcessors;
} SYSTEM_BASIC_INFORMATION, *PSYSTEM_BASIC_INFORMATION;

typedef struct _BASE_STATIC_SERVER_DATA
{
	//UNICODE_STRING WindowsDirectory;	//+0
	//UNICODE_STRING WindowsSystemDirectory;	//+8
	//UNICODE_STRING NamedObjectDirectory;	//+10
	//USHORT WindowsMajorVersion;		//+18
	//USHORT WindowsMinorVersion;		//+1A
	//USHORT BuildNumber;		//+1C
	//USHORT CSDNumber;		//+1E
	//USHORT RCNumber;		//+20
	//WCHAR CSDVersion[128];	//+22
	SYSTEM_BASIC_INFORMATION SysInfo;	//+124
	//ULONG Reserved;	//+124
	//ULONG TimerResolution;	//+128
	//ULONG PageSize;	//+12C
	//ULONG NumberOfPhysicalPages;	//+130
	//ULONG LowestPhysicalPageNumber;	//+134
	//ULONG HighestPhysicalPageNumber;	//+138
	//ULONG AllocationGranularity;	//+13C
	//ULONG_PTR MinimumUserModeAddress;	//+140
	//ULONG_PTR MaximumUserModeAddress;	//+144
	//ULONG_PTR ActiveProcessorsAffinityMask;	//+148
	//CCHAR NumberOfProcessors;	//+14C
	//+150
	//SYSTEM_TIMEOFDAY_INFORMATION TimeOfDay;
	//PVOID IniFileMapping;
	//NLS_USER_INFO NlsUserInfo;
	//BOOLEAN DefaultSeparateVDM;
	//BOOLEAN IsWowTaskReady;
	//UNICODE_STRING WindowsSys32x86Directory;
	//BOOLEAN fTermsrvAppInstallMode;
	//TIME_ZONE_INFORMATION tziTermsrvClientTimeZone;
	//KSYSTEM_TIME ktTermsrvClientBias;
	//ULONG TermsrvClientTimeZoneId;
	//BOOLEAN LUIDDeviceMapsEnabled;
	//ULONG TermsrvClientTimeZoneChangeNum;
} BASE_STATIC_SERVER_DATA, *PBASE_STATIC_SERVER_DATA;

typedef struct _EXCEPTION_REGISTRATION_RECORD
{
	_EXCEPTION_REGISTRATION_RECORD* Next;
	EXCEPTION_DISPOSITION* Handler;
} EXCEPTION_REGISTRATION_RECORD;

extern "C"
{
	PVOID NTAPI
		RtlAllocateHeap( 
		IN PVOID  HeapHandle,
		IN ULONG  Flags,
		IN SIZE_T  Size
		); 

	BOOLEAN NTAPI
		RtlFreeHeap( 
		IN PVOID  HeapHandle,
		IN ULONG  Flags,
		IN PVOID  HeapBase
		); 

	NTSTATUS NTAPI
		NtAllocateVirtualMemory(
		__in HANDLE  ProcessHandle,
		__inout PVOID  *BaseAddress,
		__in ULONG_PTR  ZeroBits,
		__inout PSIZE_T  RegionSize,
		__in ULONG  AllocationType,
		__in ULONG  Protect
		);

	NTSTATUS NTAPI
		NtFreeVirtualMemory(
		__in HANDLE  ProcessHandle,
		__inout PVOID  *BaseAddress,
		__inout PSIZE_T  RegionSize,
		__in ULONG  FreeType
		); 

	NTSTATUS NTAPI NtProtectVirtualMemory(
		__in HANDLE ProcessHandle,
		__inout PVOID * BaseAddress,
		__inout PSIZE_T RegionSize,
		__in ULONG NewProtectWin32,
		__out PULONG OldProtect
		);

	NTSTATUS NTAPI
		NtSetInformationProcess(
		IN HANDLE ProcessHandle,
		IN PROCESSINFOCLASS ProcessInformationClass,
		IN PVOID ProcessInformation,
		IN ULONG ProcessInformationLength
		);

	VOID NTAPI
		RtlInitializeBitMap(
		IN PRTL_BITMAP  BitMapHeader,
		IN PULONG  BitMapBuffer,
		IN ULONG  SizeOfBitMap
		); 

	VOID NTAPI
		RtlSetBits(
		IN PRTL_BITMAP  BitMapHeader,
		IN ULONG  StartingIndex,
		IN ULONG  NumberToSet
		); 

	VOID NTAPI
		RtlClearBits(
		IN PRTL_BITMAP  BitMapHeader,
		IN ULONG  StartingIndex,
		IN ULONG  NumberToClear
		); 

	ULONG NTAPI
		RtlFindClearBitsAndSet(
		IN PRTL_BITMAP  BitMapHeader,
		IN ULONG  NumberToFind,
		IN ULONG  HintIndex
		); 

	BOOLEAN NTAPI
		RtlAreBitsSet(
		IN PRTL_BITMAP  BitMapHeader,
		IN ULONG  StartingIndex,
		IN ULONG  Length
		); 

	PVOID NTAPI RtlDecodePointer(PVOID Ptr);
	LONG NTAPI RtlUnhandledExceptionFilter(EXCEPTION_POINTERS* ExceptionInformation);
	VOID NTAPI RtlSetLastWin32Error(DWORD Win32ErrorCode);
	ULONG NTAPI RtlNtStatusToDosError(NTSTATUS Status);
	PIMAGE_NT_HEADERS NTAPI RtlImageNtHeader(PVOID ImageBase);
	VOID NTAPI RtlInitializeSRWLock(RTL_SRWLOCK* SRWLock);
	VOID NTAPI RtlAcquireSRWLockExclusive(RTL_SRWLOCK* SRWLock);
	VOID NTAPI RtlReleaseSRWLockExclusive(RTL_SRWLOCK* SRWLock);
	VOID NTAPI RtlAcquireSRWLockShared(RTL_SRWLOCK* SRWLock);
	VOID NTAPI RtlReleaseSRWLockShared(RTL_SRWLOCK* SRWLock);
};

#define NT_SUCCESS(Status)	(((NTSTATUS)(Status)) >= 0)
#define	RtlGetProcessHeap()	(NtCurrentTeb()->ProcessEnvironmentBlock->ProcessHeap)

extern DWORD BaseDllTag;
extern BASE_STATIC_SERVER_DATA* BaseStaticServerData;

//XP有 Win7有
DWORD WINAPI BaseSetLastNTError(NTSTATUS NtStatus);

//XP没有 Win7有
VOID NTAPI RtlInitializeExceptionChain(EXCEPTION_REGISTRATION_RECORD* ExceptionRegistrationRecord);

//XP没有 Win7有（未导出）
VOID NTAPI RtlpInitializeActivationContextStack(ACTIVATION_CONTEXT_STACK* ActivationContextStack);
//XP没有 Win7有
NTSTATUS NTAPI RtlAllocateActivationContextStack(ACTIVATION_CONTEXT_STACK** ActivationContextStackOut);
//XP没有 Win7有
VOID NTAPI RtlFreeActivationContextStack(ACTIVATION_CONTEXT_STACK* ActivationContextStack);
//XP有 Win7有
VOID NTAPI RtlReleaseActivationContext(PVOID ActivationContext);
//XP没有 Win7有（未导出）
VOID NTAPI RtlpFreeActivationContextStackFrame(ACTIVATION_CONTEXT_STACK* ActivationContextStack,RTL_ACTIVATION_CONTEXT_STACK_FRAME* ActiveFrame);

//XP没有 Win7有
NTSTATUS NTAPI RtlCreateUserStack(ULONG StackCommitSize,ULONG StackReserveSize,ULONG ZeroBits,ULONG CommitAlign,ULONG ReserveAlign,INITIAL_TEB* InitialTeb);
//XP没有 Win7有
VOID NTAPI RtlFreeUserStack(PVOID Address);
//XP有 Win7有
NTSTATUS NTAPI RtlExitUserThread(ULONG ExitCode);