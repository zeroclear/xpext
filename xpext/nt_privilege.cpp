
#include "common.h"

extern "C"
{
	NTSTATUS NTAPI
		NtOpenThreadTokenEx(
		IN HANDLE ThreadHandle,
		IN ACCESS_MASK DesiredAccess,
		IN BOOLEAN OpenAsSelf,
		IN ULONG HandleAttributes,
		OUT PHANDLE TokenHandle
		);

	NTSTATUS NTAPI
		NtOpenProcessTokenEx(
		IN HANDLE ProcessHandle,
		IN ACCESS_MASK DesiredAccess,
		IN ULONG HandleAttributes,
		OUT PHANDLE TokenHandle
		);

	NTSTATUS NTAPI
		NtAdjustPrivilegesToken (
		IN HANDLE TokenHandle,
		IN BOOLEAN DisableAllPrivileges,
		IN PTOKEN_PRIVILEGES NewState OPTIONAL,
		IN ULONG BufferLength OPTIONAL,
		OUT PTOKEN_PRIVILEGES PreviousState OPTIONAL,
		OUT PULONG ReturnLength
		);

	NTSTATUS NTAPI
		NtDuplicateToken(
		IN HANDLE ExistingTokenHandle,
		IN ACCESS_MASK DesiredAccess,
		IN POBJECT_ATTRIBUTES ObjectAttributes,
		IN BOOLEAN EffectiveOnly,
		IN TOKEN_TYPE TokenType,
		OUT PHANDLE NewTokenHandle
		);
};

NTSTATUS NTAPI RtlpOpenThreadToken(ACCESS_MASK DesiredAccess,PHANDLE TokenHandle)
{
	//#define OBJ_KERNEL_HANDLE       0x00000200L
	NTSTATUS Result=NtOpenThreadTokenEx(NtCurrentThread(),DesiredAccess,TRUE,0x200,TokenHandle);
	if (!NT_SUCCESS(Result))
		Result=NtOpenThreadTokenEx(NtCurrentThread(),DesiredAccess,FALSE,0x200,TokenHandle);
	return Result;
}

enum PRIVILEGE_LUID_INDEX
{
	SeCreateTokenPrivilege=2,
	SeAssignPrimaryTokenPrivilege=3,
	SeLockMemoryPrivilege=4,
	SeIncreaseQuotaPrivilege=5,
	SeUnsolicitedInputPrivilege=6,	//Unsolicited Input is obsolete and unused.
	SeMachineAccountPrivilege=6,
	SeTcbPrivilege=7,
	SeSecurityPrivilege=8,
	SeTakeOwnershipPrivilege=9,
	SeLoadDriverPrivilege=10,
	SeSystemProfilePrivilege=11,
	SeSystemtimePrivilege=12,
	SeProfileSingleProcessPrivilege=13,
	SeIncreaseBasePriorityPrivilege=14,
	SeCreatePagefilePrivilege=15,
	SeCreatePermanentPrivilege=16,
	SeBackupPrivilege=17,
	SeRestorePrivilege=18,
	SeShutdownPrivilege=19,
	SeDebugPrivilege=20,
	SeAuditPrivilege=21,
	SeSystemEnvironmentPrivilege=22,
	SeChangeNotifyPrivilege=23,
	SeRemoteShutdownPrivilege=24,
	SeUndockPrivilege=25,
	SeSyncAgentPrivilege=26,
	SeEnableDelegationPrivilege=27,
	SeManageVolumePrivilege=28,
	SeImpersonatePrivilege=29,
	SeCreateGlobalPrivilege=30,
	MaxPrivilegeLuidIndex_XP=31,

	SeTrustedCredManAccessPrivilege=31,
	SeRelabelPrivilege=32,
	SeIncreaseWorkingSetPrivilege=33,
	SeTimeZonePrivilege=34,
	SeCreateSymbolicLinkPrivilege=35,
	MaxPrivilegeLuidIndex_W7=36,
};

//RtlAcquirePrivilege和RtlReleasePrivilege大部分照搬了ReactOS的rtltypes.h和priv.c（Latest commit c2c66af on 3 Oct 2017）
//细节有所改动，不同之处以Win7为准（ntdll.dll  x86  6.1.7601.17514）
#define RTL_ACQUIRE_PRIVILEGE_IMPERSONATE                   1
#define RTL_ACQUIRE_PRIVILEGE_PROCESS                       2

typedef struct _RTL_ACQUIRE_STATE
{
	HANDLE Token;
	HANDLE OldImpersonationToken;
	PTOKEN_PRIVILEGES OldPrivileges;
	PTOKEN_PRIVILEGES NewPrivileges;
	ULONG Flags;
	UCHAR OldPrivBuffer[1024];
} RTL_ACQUIRE_STATE, *PRTL_ACQUIRE_STATE;

NTSTATUS
NTAPI
RtlAcquirePrivilege(IN PULONG Privilege,
                    IN ULONG NumPriv,
                    IN ULONG Flags,
                    OUT PVOID *ReturnedState)
{
	//ULONG ReturnLength由AdjustSize代替，NTSTATUS IntStatus不用了
	//C++03支持循环内定义i，OldSize合并到AdjustSize
    PRTL_ACQUIRE_STATE State;
    NTSTATUS Status;
    //ULONG i, OldSize;
	ULONG AdjustSize;
    SECURITY_QUALITY_OF_SERVICE Sqos;
    OBJECT_ATTRIBUTES ObjectAttributes;
    HANDLE ImpersonationToken, ProcessToken;

	//ReactOS里用的是RtlGetProcessHeap()，全部替换成HeapHandle
	//另外，在Win7原版的调用中，RtlAllocateHeap的Flags是NtdllBaseTag+0x140000
	//NtdllBaseTag=RtlCreateTagHeap(LdrpHeap,0,"NTDLL!","!Process");
	//可以理解为RtlCreateTagHeap创建了一个子堆，然后返回Index<<18
	//NtdllBaseTag是第一个创建的，索引为0，后续的子堆，用NtdllBaseTag+(Index<<18)就能访问
	//而真正的Flags在低位，与Index相加组合，并不冲突
	PVOID HeapHandle=NtCurrentTeb()->ProcessEnvironmentBlock->ProcessHeap;

    //DPRINT("RtlAcquirePrivilege(%p, %u, %u, %p)\n", Privilege, NumPriv, Flags, ReturnedState);

    /* Validate flags */
    if (Flags & ~(RTL_ACQUIRE_PRIVILEGE_PROCESS | RTL_ACQUIRE_PRIVILEGE_IMPERSONATE))
    {
        return STATUS_INVALID_PARAMETER;
    }

    /* If user wants to acquire privileges for the process, we have to impersonate him */
    if (Flags & RTL_ACQUIRE_PRIVILEGE_PROCESS)
    {
        Flags |= RTL_ACQUIRE_PRIVILEGE_IMPERSONATE;
    }

    /* Allocate enough memory to hold: old privileges (fixed buffer size, might not be enough)
     *                                 new privileges (big enough, after old privileges memory area)
     */
    State = (PRTL_ACQUIRE_STATE)RtlAllocateHeap(HeapHandle, 0, sizeof(RTL_ACQUIRE_STATE) + sizeof(TOKEN_PRIVILEGES) +
                                                    (NumPriv - ANYSIZE_ARRAY) * sizeof(LUID_AND_ATTRIBUTES));
    if (!State)
    {
        return STATUS_NO_MEMORY;
    }

    /* Only zero a bit of the memory (will be faster that way) */
    State->Token = 0;
    State->OldImpersonationToken = 0;
    State->Flags = 0;
    //State->OldPrivileges = NULL;

    /* Check whether we have already an active impersonation */
    if (NtCurrentTeb()->IsImpersonating)
    {
		//ReactOS的判断和Win7汇编代码正好相反，以Win7为准
        /* Check whether we want to impersonate */
        if ((Flags&RTL_ACQUIRE_PRIVILEGE_IMPERSONATE)==0)
        {
            /* That's all fine, just get the token.
             * We need access for: adjust (obvious...) but also
             *                     query, to be able to query old privileges
             */
            Status = RtlpOpenThreadToken(TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &State->Token);
            if (!NT_SUCCESS(Status))
            {
                RtlFreeHeap(HeapHandle, 0, State);
                return Status;
            }
        }
        else
        {
            /* Otherwise, we have to temporary disable active impersonation.
             * Get previous impersonation token to save it
             */
            Status = RtlpOpenThreadToken(TOKEN_IMPERSONATE, &State->OldImpersonationToken);
            if (!NT_SUCCESS(Status))
            {
                RtlFreeHeap(HeapHandle, 0, State);
                return Status;
            }

            /* Remember the fact we had an active impersonation */
            State->Flags |= RTL_ACQUIRE_PRIVILEGE_IMPERSONATE;

			//Win7专门用var_10完成，实际上重复用这一个就够了
			ImpersonationToken=NULL;
            /* Revert impersonation (ie, give 0 as handle) */
            Status = NtSetInformationThread(NtCurrentThread(),
                                            ThreadImpersonationToken,
                                            &ImpersonationToken,
                                            sizeof(HANDLE));
        }
    }

    /* If we have no token yet (which is likely) */
    if (!State->Token)	//IsImpersonating为FALSE时，Token必然为NULL，流程与汇编一致
    {
        /* If we are asked to use process, then do */
        if (Flags & RTL_ACQUIRE_PRIVILEGE_PROCESS)
        {
			//ReactOS使用NtOpenProcessToken，而Win7使用NtOpenProcessTokenEx，全部替换
            Status = NtOpenProcessTokenEx(NtCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
									0x200, &State->Token);
            if (!NT_SUCCESS(Status))
            {
                goto Cleanup;
            }

			//ReactOS漏了
			State->Flags|=RTL_ACQUIRE_PRIVILEGE_PROCESS;
        }
        else
        {
            /* Otherwise, we have to impersonate.
             * Open token for duplication
             */
            Status = NtOpenProcessTokenEx(NtCurrentProcess(), TOKEN_DUPLICATE, 0x200, &ProcessToken);

			InitializeObjectAttributes(&ObjectAttributes,
				NULL,
				0,
				NULL,
				NULL);

			ObjectAttributes.SecurityQualityOfService = &Sqos;
			Sqos.Length = sizeof(SECURITY_QUALITY_OF_SERVICE);
			Sqos.ImpersonationLevel = SecurityDelegation;
			Sqos.ContextTrackingMode = 1;
			Sqos.EffectiveOnly = FALSE;

			//ReactOS的代码相比Win7少了NtOpenProcessTokenEx结果的判断
			//这里整理成Win7汇编的形式
			if (NT_SUCCESS(Status))
			{
				/* Duplicate */
				Status = NtDuplicateToken(ProcessToken,
					TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY | TOKEN_IMPERSONATE,
					&ObjectAttributes,
					FALSE,
					TokenImpersonation,
					&ImpersonationToken);

				if (NT_SUCCESS(Status))
				{
					/* Assign our duplicated token to current thread */
					Status = NtSetInformationThread(NtCurrentThread(),
						ThreadImpersonationToken,
						&ImpersonationToken,
						sizeof(HANDLE));

					if (NT_SUCCESS(Status))
					{
						/* Save said token and the fact we have impersonated */
						State->Token = ImpersonationToken;
					}
					else
					{
						NtClose(ImpersonationToken);
					}
				}
				NtClose(ProcessToken);
			}

			if (!NT_SUCCESS(Status))
			{
				goto Cleanup;
			}

			State->Flags |= RTL_ACQUIRE_PRIVILEGE_IMPERSONATE;
        }
    }

    /* Properly set the privileges pointers:
     * OldPrivileges points to the static memory in struct (= OldPrivBuffer)
     * NewPrivileges points to the dynamic memory after OldPrivBuffer
     * There's NO overflow risks (OldPrivileges is always used with its size)
     */
    State->OldPrivileges = (PTOKEN_PRIVILEGES)State->OldPrivBuffer;
    State->NewPrivileges = (PTOKEN_PRIVILEGES)(State->OldPrivBuffer + (sizeof(State->OldPrivBuffer) / sizeof(State->OldPrivBuffer[0])));

	/*
	RTL_ACQUIRE_STATE::Token;					+0
	RTL_ACQUIRE_STATE::OldImpersonationToken;	+4
	RTL_ACQUIRE_STATE::OldPrivileges;			+8
	RTL_ACQUIRE_STATE::NewPrivileges;			+C
	RTL_ACQUIRE_STATE::Flags;					+10
	RTL_ACQUIRE_STATE::OldPrivBuffer[1024];		+14
	TOKEN_PRIVILEGES NewPrivilegesBuffer;		+414
	{
		TOKEN_PRIVILEGES::PrivilegeCount;					+0
		TOKEN_PRIVILEGES::Privileges[0]::Luid::LowPart;		+4
		TOKEN_PRIVILEGES::Privileges[0]::Luid::HighPart;	+8
		TOKEN_PRIVILEGES::Privileges[0]::Attributes;		+C
		TOKEN_PRIVILEGES::Privileges[1]::Luid::LowPart;		+10
		TOKEN_PRIVILEGES::Privileges[1]::Luid::HighPart;	+14
		TOKEN_PRIVILEGES::Privileges[1]::Attributes;		+18
		...
	}
	*/

    /* Assign all the privileges to be acquired */
    State->NewPrivileges->PrivilegeCount = NumPriv;
    for (ULONG i = 0; i < NumPriv; ++i)
    {
        State->NewPrivileges->Privileges[i].Luid.LowPart = Privilege[i];
        State->NewPrivileges->Privileges[i].Luid.HighPart = 0;
        State->NewPrivileges->Privileges[i].Attributes = SE_PRIVILEGE_ENABLED;
    }

    /* Start privileges adjustements */
	//ReactOS版与Win7结构差距太大，剩下的部分按汇编改写
	AdjustSize=sizeof(State->OldPrivBuffer);
	Status = NtAdjustPrivilegesToken(State->Token, FALSE, State->NewPrivileges,
		AdjustSize, State->OldPrivileges, &AdjustSize);
	/* This is returned when OldPrivileges buffer is too small */
	if (Status==STATUS_BUFFER_TOO_SMALL)
	{
		while (1)
		{
			/* Try to allocate a new one, big enough to hold data */
			State->OldPrivileges=(PTOKEN_PRIVILEGES)RtlAllocateHeap(HeapHandle,0,AdjustSize);
			if (State->OldPrivileges==NULL)
			{
				/* If we failed, properly set status: we failed because of the lack of memory */
				Status=STATUS_NO_MEMORY;
				break;
			}
			Status = NtAdjustPrivilegesToken(State->Token, FALSE, State->NewPrivileges,
				AdjustSize, State->OldPrivileges, &AdjustSize);
			if (Status!=STATUS_BUFFER_TOO_SMALL)
			{
				break;
			}
			RtlFreeHeap(HeapHandle,0,State->OldPrivileges);
		}
	}

	/* If we failed to assign at least one privilege */
	if (Status==STATUS_NOT_ALL_ASSIGNED)
	{
		/* If there was actually only one privilege to acquire, use more accurate status */
		if (NumPriv==1)
			Status=STATUS_PRIVILEGE_NOT_HELD;
		else
			Status=STATUS_SUCCESS;
	}
	/* Fail if needed, otherwise return our state to caller */
	if (NT_SUCCESS(Status))
	{
		*ReturnedState=State;
		//DPRINT("RtlAcquirePrivilege succeed!\n");
		return STATUS_SUCCESS;
	}

	/* If we allocated our own buffer for old privileges, release it */
	if (State->OldPrivileges && (PVOID)State->OldPrivBuffer != (PVOID)State->OldPrivileges)
	{
		RtlFreeHeap(HeapHandle, 0, State->OldPrivileges);
	}
	/* Release token */
	//if (State->Token)
	NtClose(State->Token);

Cleanup:
	/* Do we have to restore previously active impersonation? */
	if (State->Flags & RTL_ACQUIRE_PRIVILEGE_IMPERSONATE)
	{
		//IntStatus =
		NtSetInformationThread(NtCurrentThread(), ThreadImpersonationToken,
			&State->OldImpersonationToken, sizeof(HANDLE));
		//if (!NT_SUCCESS(IntStatus))  RtlRaiseStatus(IntStatus);
		if (State->OldImpersonationToken!=NULL)
		{
			NtClose(State->OldImpersonationToken);
		}
	}
	/* And free our state buffer */
	RtlFreeHeap(HeapHandle, 0, State);

	//DPRINT("RtlAcquirePrivilege() failed with status: %lx\n", Status);
	return Status;
}

VOID
NTAPI
RtlReleasePrivilege(IN PVOID ReturnedState)
{
    NTSTATUS Status;
    PRTL_ACQUIRE_STATE State = (PRTL_ACQUIRE_STATE)ReturnedState;

    //DPRINT("RtlReleasePrivilege(%p)\n", ReturnedState);

	//ReactOS里用的是RtlGetProcessHeap()，全部替换成HeapHandle
	PVOID HeapHandle=NtCurrentTeb()->ProcessEnvironmentBlock->ProcessHeap;

    /* If we had an active impersonation before we acquired privileges
     * Or if we have impersonated, quit it
     */
    //if (State->Flags & RTL_ACQUIRE_PRIVILEGE_IMPERSONATE) {NtSetInformationThread()...}
    //else {NtAdjustPrivilegesToken()...}
	//ReactOS和Win7的代码理论上是等价的，这里改成了Win7的形式
	//!(Flags&1)对应0和2，(Flags&1)&&(Flags&2)对应3
	if ((State->Flags&RTL_ACQUIRE_PRIVILEGE_IMPERSONATE)==0 || (State->Flags&RTL_ACQUIRE_PRIVILEGE_PROCESS)!=0)
	{
        /* Otherwise, restore old state */
        NtAdjustPrivilegesToken(State->Token, FALSE,
                                State->OldPrivileges, 0, NULL, NULL);
	}
	//(Flags&1)对应1
	else if (State->Flags&RTL_ACQUIRE_PRIVILEGE_IMPERSONATE)
	{
        /* Restore it for the current thread */
        Status = NtSetInformationThread(NtCurrentThread(), ThreadImpersonationToken,
                                        &State->OldImpersonationToken, sizeof(HANDLE));
        //if (!NT_SUCCESS(Status))
        //{
        //    RtlRaiseStatus(Status);
        //}

        /* And close the token if needed */
        if (State->OldImpersonationToken)
            NtClose(State->OldImpersonationToken);
	}

    /* If we used a different buffer for old privileges, just free it */
    if ((PVOID)State->OldPrivBuffer != (PVOID)State->OldPrivileges)
    {
        //DPRINT("Releasing old privileges: %p\n", State->OldPrivileges);
        RtlFreeHeap(HeapHandle, 0, State->OldPrivileges);
    }

    /* Release token and free state */
    NtClose(State->Token);
    RtlFreeHeap(HeapHandle, 0, State);
}
