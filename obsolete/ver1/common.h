
#include <Windows.h>
#include <intrin.h>  
 
typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR Buffer;
} UNICODE_STRING, *PUNICODE_STRING;
typedef CONST UNICODE_STRING *PCUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
	ULONG Length;
	HANDLE RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG Attributes;
	PVOID SecurityDescriptor;
	PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;
typedef CONST OBJECT_ATTRIBUTES *PCOBJECT_ATTRIBUTES;

typedef struct _PEB_LDR_DATA
{
	ULONG Length;
	BOOLEAN Initialized;
	PVOID SsHandle;
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
	ULONG EntryInProgress;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _LDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	USHORT LoadCount;
	USHORT TlsIndex;
	union 
	{
		LIST_ENTRY HashLinks;
		struct 
		{
			PVOID SectionPointer;
			ULONG CheckSum;
		};
	};
	union 
	{
		ULONG TimeDateStamp;
		PVOID LoadedImports;
	};
	PVOID EntryPointActivationContext;
	PVOID PatchInformation;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

/*
typedef struct _PEB_FREE_BLOCK
{
	_PEB_FREE_BLOCK* Next;
	ULONG Size;
} PEB_FREE_BLOCK;
*/

typedef struct _PEB
{
	UCHAR InheritedAddressSpace;	//+0x000
	UCHAR ReadImageFileExecOptions;	//+0x001
	UCHAR BeingDebugged;	//+0x002
	UCHAR SpareBool;	//+0x003
	PVOID Mutant;	//+0x004
	PVOID ImageBaseAddress;	//+0x008
	PEB_LDR_DATA* Ldr;	//+0x00c
	PVOID ProcessParameters;	//+0x010 RTL_USER_PROCESS_PARAMETERS*
	PVOID SubSystemData;	//+0x014
	PVOID ProcessHeap;	//+0x018
	RTL_CRITICAL_SECTION* FastPebLock;	//+0x01c
	PVOID FastPebLockRoutine;	//+0x020
	PVOID FastPebUnlockRoutine;	//+0x024
	ULONG EnvironmentUpdateCount;	//+0x028
	PVOID KernelCallbackTable;	//+0x02c
	ULONG SystemReserved[1];	//+0x030
	ULONG AtlThunkSListPtr32;	//+0x034
	PVOID FreeList;	//+0x038 PEB_FREE_BLOCK*
	ULONG TlsExpansionCounter;	//+0x03c
	PVOID TlsBitmap;	//+0x040
	ULONG TlsBitmapBits[2];	//+0x044
	PVOID ReadOnlySharedMemoryBase;	//+0x04c
	PVOID ReadOnlySharedMemoryHeap;	//+0x050
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
	PVOID LoaderLock;	//+0x0a0
	ULONG OSMajorVersion;	//+0x0a4
	ULONG OSMinorVersion;	//+0x0a8
	USHORT OSBuildNumber;	//+0x0ac
	USHORT OSCSDVersion;	//+0x0ae
	ULONG OSPlatformId;	//+0x0b0
	ULONG ImageSubsystem;	//+0x0b4
	ULONG ImageSubsystemMajorVersion;	//+0x0b8
	ULONG ImageSubsystemMinorVersion;	//+0x0bc
	ULONG ImageProcessAffinityMask;	//+0x0c0
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
	PVOID ActivationContextData;	//+0x1f8
	PVOID ProcessAssemblyStorageMap;	//+0x1fc
	PVOID SystemDefaultActivationContextData;	//+0x200
	PVOID SystemAssemblyStorageMap;	//+0x204
	ULONG MinimumStackCommit;	//+0x208
} PEB;

typedef struct _CLIENT_ID
{
	PVOID UniqueProcess;
	PVOID UniqueThread;
} CLIENT_ID;

typedef struct _ACTIVATION_CONTEXT_STACK
{
	ULONG Flags;
	ULONG NextCookieSequenceNumber;
	PVOID ActiveFrame;
	LIST_ENTRY FrameListCache;
} ACTIVATION_CONTEXT_STACK;

typedef struct _GDI_TEB_BATCH
{
	ULONG Offset;
	ULONG hDC;
	ULONG Buffer[310];
} GDI_TEB_BATCH;

typedef struct _Wx86ThreadState
{
	ULONG* CallBx86Eip;
	PVOID DeallocationCpu;
	UCHAR UseKnownWx86Dll;
	CHAR OleStubInvoked;
} Wx86ThreadState;

/*
typedef struct _TEB_ACTIVE_FRAME_CONTEXT
{
	ULONG Flags;
	CHAR* FrameName;
} TEB_ACTIVE_FRAME_CONTEXT;

typedef struct _TEB_ACTIVE_FRAME
{
	ULONG Flags;
	_TEB_ACTIVE_FRAME* Previous;
	TEB_ACTIVE_FRAME_CONTEXT* Context;
} TEB_ACTIVE_FRAME;
*/

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
	ACTIVATION_CONTEXT_STACK ActivationContextStack;	//+0x1a8
	UCHAR SpareBytes1[24];	//+0x1bc
	GDI_TEB_BATCH GdiTebBatch;	//+0x1d4
	CLIENT_ID RealClientId;	//+0x6b4
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
	USHORT StaticUnicodeBuffer[261];	//+0xc00
	PVOID DeallocationStack;	//+0xe0c
	PVOID TlsSlots[64];	//+0xe10
	LIST_ENTRY TlsLinks;	//+0xf10
	PVOID Vdm;	//+0xf18
	PVOID ReservedForNtRpc;	//+0xf1c
	PVOID DbgSsReserved[2];	//+0xf20
	ULONG HardErrorsAreDisabled;	//+0xf28
	PVOID Instrumentation[16];	//+0xf2c
	PVOID WinSockData;	//+0xf6c
	ULONG GdiBatchCount;	//+0xf70
	UCHAR InDbgPrint;	//+0xf74
	UCHAR FreeStackOnTermination;	//+0xf75
	UCHAR HasFiberData;	//+0xf76
	UCHAR IdealProcessor;	//+0xf77
	ULONG Spare3;	//+0xf78
	PVOID ReservedForPerf;	//+0xf7c
	PVOID ReservedForOle;	//+0xf80
	ULONG WaitingOnLoaderLock;	//+0xf84
	Wx86ThreadState Wx86Thread;	//+0xf88
	PVOID* TlsExpansionSlots;	//+0xf94
	ULONG ImpersonationLocale;	//+0xf98
	ULONG IsImpersonating;	//+0xf9c
	PVOID NlsCache;	//+0xfa0
	PVOID pShimData;	//+0xfa4
	ULONG HeapVirtualAffinity;	//+0xfa8
	PVOID CurrentTransactionHandle;	//+0xfac
	PVOID ActiveFrame;	//+0xfb0 TEB_ACTIVE_FRAME*
	UCHAR SafeThunkCall;	//+0xfb4
	UCHAR BooleanSpare[3];	//+0xfb5
} TEB;

typedef struct _KSYSTEM_TIME
{
	ULONG LowPart;
	LONG High1Time;
	LONG High2Time;
} KSYSTEM_TIME;

enum _NT_PRODUCT_TYPE
{
	NtProductWinNt=1,
	NtProductLanManNt=2,
	NtProductServer=3
};
typedef _NT_PRODUCT_TYPE NT_PRODUCT_TYPE;

enum _ALTERNATIVE_ARCHITECTURE_TYPE
{
	StandardDesign=0,
	NEC98x86=1,
	EndAlternatives=2
};
typedef _ALTERNATIVE_ARCHITECTURE_TYPE ALTERNATIVE_ARCHITECTURE_TYPE;

typedef struct _KUSER_SHARED_DATA
{
	ULONG TickCountLow;	//+0x000
	ULONG TickCountMultiplier;	//+0x004
	KSYSTEM_TIME InterruptTime;	//+0x008
	KSYSTEM_TIME SystemTime;	//+0x014
	KSYSTEM_TIME TimeZoneBias;	//+0x020
	USHORT ImageNumberLow;	//+0x02c
	USHORT ImageNumberHigh;	//+0x02e
	USHORT NtSystemRoot[260];	//+0x030
	ULONG MaxStackTraceDepth;	//+0x238
	ULONG CryptoExponent;	//+0x23c
	ULONG TimeZoneId;	//+0x240
	ULONG Reserved2[8];	//+0x244
	NT_PRODUCT_TYPE NtProductType;	//+0x264
	UCHAR ProductTypeIsValid;	//+0x268
	ULONG NtMajorVersion;	//+0x26c
	ULONG NtMinorVersion;	//+0x270
	UCHAR ProcessorFeatures[64];	//+0x274
	ULONG Reserved1;	//+0x2b4
	ULONG Reserved3;	//+0x2b8
	ULONG TimeSlip;	//+0x2bc
	ALTERNATIVE_ARCHITECTURE_TYPE AlternativeArchitecture;	//+0x2c0
	LARGE_INTEGER SystemExpirationDate;	//+0x2c8
	ULONG SuiteMask;	//+0x2d0
	UCHAR KdDebuggerEnabled;	//+0x2d4
	UCHAR NXSupportPolicy;	//+0x2d5
	ULONG ActiveConsoleId;	//+0x2d8
	ULONG DismountCount;	//+0x2dc
	ULONG ComPlusPackage;	//+0x2e0
	ULONG LastSystemRITEventTickCount;	//+0x2e4
	ULONG NumberOfPhysicalPages;	//+0x2e8
	UCHAR SafeBootMode;	//+0x2ec
	ULONG TraceLogging;	//+0x2f0
	ULONGLONG TestRetInstruction;	//+0x2f8
	ULONG SystemCall;	//+0x300
	ULONG SystemCallReturn;	//+0x304
	ULONGLONG SystemCallPad[3];	//+0x308
	union
	{
		KSYSTEM_TIME TickCount;	//+0x320
		ULONGLONG TickCountQuad;	//+0x320
	};
	ULONG Cookie;	//+0x330
} KUSER_SHARED_DATA;


extern "C"
{
	NTSTATUS NTAPI NtCreateKeyedEvent(OUT PHANDLE handle, IN ACCESS_MASK access, IN POBJECT_ATTRIBUTES attr, IN ULONG flags);
	NTSTATUS NTAPI NtOpenKeyedEvent(OUT PHANDLE handle, IN ACCESS_MASK access, IN POBJECT_ATTRIBUTES attr);
	NTSTATUS NTAPI NtWaitForKeyedEvent(IN HANDLE handle, IN PVOID key, IN BOOLEAN alertable, IN PLARGE_INTEGER mstimeout);
	NTSTATUS NTAPI NtReleaseKeyedEvent(IN HANDLE handle, IN PVOID key, IN BOOLEAN alertable, IN PLARGE_INTEGER mstimeout);
	NTSTATUS NTAPI ZwTerminateProcess(IN HANDLE  ProcessHandle, IN NTSTATUS  ExitStatus);
	NTSTATUS NTAPI NtClose(IN HANDLE Handle);
	VOID NTAPI RtlRaiseStatus(NTSTATUS Status);
	VOID NTAPI RtlInitUnicodeString(PUNICODE_STRING DestinationString,PCWSTR SourceString);
	LONG NTAPI RtlCompareUnicodeString(PCUNICODE_STRING String1,PCUNICODE_STRING String2,BOOLEAN CaseInSensitive);
	NTSTATUS NTAPI RtlInitializeCriticalSectionAndSpinCount(PRTL_CRITICAL_SECTION lpCriticalSection,DWORD dwSpinCount);
	NTSTATUS NTAPI RtlEnterCriticalSection(PRTL_CRITICAL_SECTION lpCriticalSection);
	NTSTATUS NTAPI RtlLeaveCriticalSection(PRTL_CRITICAL_SECTION lpCriticalSection);
	VOID NTAPI DbgBreakPoint();
	ULONG NTAPI RtlNtStatusToDosError(NTSTATUS Status);
};

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#define STATUS_SUCCESS	0

PVOID WINAPI FindDllBase(WCHAR* szName);
HANDLE NTAPI OpenGlobalKeyedEvent();
void NTAPI CloseGlobalKeyedEvent(HANDLE hKeyedEvent);
BOOL NTAPI RtlpWaitCouldDeadlock();
void NTAPI RtlBackoff(DWORD* pCount);
void WINAPI K32SetLastError(DWORD dwErrCode);
DWORD WINAPI BaseSetLastNTError(NTSTATUS NtStatus);
LARGE_INTEGER* WINAPI BaseFormatTimeOut(LARGE_INTEGER* pTimeOut,DWORD dwMilliseconds);

extern HANDLE GlobalKeyedEventHandle;
extern DWORD* g_dwLastErrorToBreakOn;	//pointer
extern BYTE* LdrpShutdownInProgress;	//pointer

void NTAPI RtlInitializeSRWLock(RTL_SRWLOCK* SRWLock);
void NTAPI RtlAcquireSRWLockExclusive(RTL_SRWLOCK* SRWLock);
void NTAPI RtlAcquireSRWLockShared(RTL_SRWLOCK* SRWLock);
void NTAPI RtlReleaseSRWLockExclusive(RTL_SRWLOCK* SRWLock);
void NTAPI RtlReleaseSRWLockShared(RTL_SRWLOCK* SRWLock);
BOOL NTAPI RtlTryAcquireSRWLockExclusive(RTL_SRWLOCK* SRWLock);
BOOL NTAPI RtlTryAcquireSRWLockShared(RTL_SRWLOCK* SRWLock);

void NTAPI RtlInitializeConditionVariable(RTL_CONDITION_VARIABLE* ConditionVariable);
NTSTATUS NTAPI RtlSleepConditionVariableCS(RTL_CONDITION_VARIABLE* ConditionVariable,RTL_CRITICAL_SECTION* CriticalSection,LARGE_INTEGER* Timeout);
NTSTATUS NTAPI RtlSleepConditionVariableSRW(RTL_CONDITION_VARIABLE* ConditionVariable,RTL_SRWLOCK* SRWLock,LARGE_INTEGER* Timeout,ULONG Flags);
void NTAPI RtlWakeConditionVariable(RTL_CONDITION_VARIABLE* ConditionVariable);
void NTAPI RtlWakeAllConditionVariable(RTL_CONDITION_VARIABLE* ConditionVariable);


//GetErrorMode=0x7C80ACDD

typedef struct _SYNCITEM
{
	_SYNCITEM* back;	//上个插入的节点
	_SYNCITEM* first;	//第一个插入的节点
	_SYNCITEM* next;	//下个插入的节点
	DWORD count;		//共享计数
	DWORD attr;			//节点属性
	RTL_SRWLOCK* lock;
} SYNCITEM;

typedef size_t SYNCSTATUS;

//M-mask F-flag SYNC-common
#define SYNC_Exclusive	1	//当前是独占锁在等待，而不是共享锁
#define SYNC_Spinning	2	//当前线程即将休眠，而不是休眠中或唤醒后
#define SYNC_SharedLock	4	//条件变量使用共享锁等待，而不是独占锁

#define SRWM_FLAG	0x0000000F
#define SRWM_ITEM	0xFFFFFFF0	//64位系统应该改成0xFFFFFFFFFFFFFFF0
#define SRWM_COUNT	SRWM_ITEM

#define SRWF_Free	0	//空闲
#define SRWF_Hold	1	//有线程拥有了锁
#define SRWF_Wait	2	//有线程正在等待
#define SRWF_Link	4	//修改链表的操作进行中
#define SRWF_Many	8	//独占请求之前有多个共享锁并存

#define CVM_COUNT	0x00000007
#define CVM_FLAG	0x0000000F
#define CVM_ITEM	0xFFFFFFF0

#define CVF_Full	7	//唤醒申请已满，全部唤醒
#define CVF_Link	8	//修改链表的操作进行中

#define SRW_COUNT_BIT	4
#define SRW_HOLD_BIT	0
#define SYNC_SPIN_BIT	1	//从0开始数
