/*+===================================================================
  File:      parse_header.c

  Summary:   Parse information from PE header of an image.

  Classes:   N/A

  Functions: N/A

  Origin:    https://github.com/am0nsec

##

  Author: Paul Laine (@am0nsec)
===================================================================+*/
#include <Windows.h>
#include <stdio.h>

/*--------------------------------------------------------------------
  STRUCTURES
--------------------------------------------------------------------*/
typedef struct _LSA_UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} LSA_UNICODE_STRING, * PLSA_UNICODE_STRING, UNICODE_STRING, * PUNICODE_STRING, * PUNICODE_STR;

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

typedef struct _PEB_LDR_DATA {
	ULONG                   Length;
	ULONG                   Initialized;
	PVOID                   SsHandle;
	LIST_ENTRY              InLoadOrderModuleList;
	LIST_ENTRY              InMemoryOrderModuleList;
	LIST_ENTRY              InInitializationOrderModuleList;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

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

/*--------------------------------------------------------------------
  FUNCTIONS DEFINITION
--------------------------------------------------------------------*/
BOOL    PlLoadLibrary(LPCWSTR szDllName);

/*--------------------------------------------------------------------
  GLOBAL VARIABLES
--------------------------------------------------------------------*/
#define SIZE_OF_IMAGE_SECTION_HEADER 0x28
DWORD64 g_dwModuleBaseAddress;

/*--------------------------------------------------------------------
  Entry Point
--------------------------------------------------------------------*/
int wmain(int argc, wchar_t* argv[], wchar_t* envp[]) {
	wprintf(L"[>] Parse PE Header\n");
	wprintf(L"[>] Author: Paul Laine (@am0nsec)\n");
	wprintf(L"    -----------------------------\n\n");

	if (argc < 2) {
		wprintf(L"[-] Missing parameter\n");
		wprintf(L"[-] Usage: %s <path to image>\n", argv[0]);
		return 0x1;
	}

	/*--------------------------------------------------------------------
	  Load the DLL into the memory space of the process
	--------------------------------------------------------------------*/
	wprintf(L"[>] Loading %s into current process ...\n", argv[1]);
	BOOL success = PlLoadLibrary(argv[1]);
	if (!success) {
		wprintf(L"[-] Unable to load: %s\n\n", argv[1]);
		return 0x1;
	}
	wprintf(L"[+] Loading %s into current process ... OK\n", argv[1]);

	PIMAGE_DOS_HEADER pImageDosHeader = (PIMAGE_DOS_HEADER)g_dwModuleBaseAddress;
	if (pImageDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		wprintf(L"[-] Invalid DOS header\n");
		return 1;
	}

	/*--------------------------------------------------------------------
	  The MS-DOS Real-Mode Stub Program being between the MS-DOS MZ header
	  and the NT Headers (PE FILE Signature + PE File Header + PE File 
	  Optional Heder), the e_lfanew variable provide address of the next
	  PE header.
    --------------------------------------------------------------------*/
	wprintf(L"\n[>] Parse PE header ...\n");
	PIMAGE_NT_HEADERS pImageNtHeader = (PIMAGE_NT_HEADERS)(g_dwModuleBaseAddress + pImageDosHeader->e_lfanew);
	if (pImageNtHeader->Signature != IMAGE_NT_SIGNATURE) {
		wprintf(L"[-] Invalid NT header\n");
		return 1;
	}

	/*--------------------------------------------------------------------
	  The IMAGE_FILE_HEADER structure is just after the NT Header signature,
	  which is a DWORD.
	--------------------------------------------------------------------*/
	PIMAGE_FILE_HEADER pImageFileHeader = (PIMAGE_FILE_HEADER)((PBYTE)pImageNtHeader + sizeof(DWORD));
	
	/*--------------------------------------------------------------------
	  The IMAGE_OPTIONAL_HEADER structure is just after the 
	  IMAGE_FILE_HEADER structure from the NT Header.
	  IMAGE_SIZEOF_FILE_HEADER = 20
	--------------------------------------------------------------------*/
	PIMAGE_OPTIONAL_HEADER pImageOptionalHeader = (PIMAGE_OPTIONAL_HEADER)((PBYTE)pImageFileHeader + IMAGE_SIZEOF_FILE_HEADER);
	if (g_dwModuleBaseAddress != pImageOptionalHeader->ImageBase) {
		wprintf(L"[-] Invalid PE optional file header\n");
		return 1;
	}
	wprintf(L"   - ImageBase:     0x%016llx\n", g_dwModuleBaseAddress);
	wprintf(L"   - Entry Point:   0x%016llx\n", (g_dwModuleBaseAddress + pImageOptionalHeader->AddressOfEntryPoint));
	wprintf(L"   - Image Version: %d.%d\n", pImageOptionalHeader->MajorImageVersion, pImageOptionalHeader->MinorImageVersion);
	wprintf(L"   - SizeOfImage:   0x%08x\n", pImageOptionalHeader->SizeOfImage);
	wprintf(L"[+] Parse PE header ... OK\n\n");


	/*--------------------------------------------------------------------
	  The IMAGE_OPTIONAL_HEADER structure is just after the IMAGE_FILE_HEADER
 	  structure from the NT Header. IMAGE_SIZEOF_FILE_HEADER = 20
	--------------------------------------------------------------------*/
	wprintf(L"[>] Parse section headers ...\n");
	for (WORD i = 0; i < pImageFileHeader->NumberOfSections; i++) {
		DWORD64 dwFirstImageSectionHeaderAddress = g_dwModuleBaseAddress + pImageDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS64);
		PIMAGE_SECTION_HEADER pImageSectionHeader = (PIMAGE_SECTION_HEADER)(dwFirstImageSectionHeaderAddress + (SIZE_OF_IMAGE_SECTION_HEADER * i));
		printf("   - 0x%016llx  %s\n", (g_dwModuleBaseAddress + pImageSectionHeader->VirtualAddress), pImageSectionHeader->Name);
	}
	wprintf(L"[+] Parse section headers ... OK\n\n");
	

	/*--------------------------------------------------------------------
	  The virtual address from the first IMAGE_DATA_DIRECTORY pointes to the
	  IMAGE_EXPORT_DIRECTORY structure, which list all the exported functions
	  of the module.
	--------------------------------------------------------------------*/
	wprintf(L"[>] Parse the export directory ... \n");
	PIMAGE_EXPORT_DIRECTORY pImageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(g_dwModuleBaseAddress + pImageOptionalHeader->DataDirectory[0].VirtualAddress);
	PDWORD pdwAddressOfFunctions = (PDWORD)(g_dwModuleBaseAddress + pImageExportDirectory->AddressOfFunctions);
	PDWORD pdwAddressOfNames = (PDWORD)(g_dwModuleBaseAddress + pImageExportDirectory->AddressOfNames);
	PWORD pwAddressOfNameOrdinales = (PWORD)(g_dwModuleBaseAddress + pImageExportDirectory->AddressOfNameOrdinals);
	wprintf(L"   - NumberOfFunctions: %d\n", pImageExportDirectory->NumberOfFunctions);

	DWORD cx;
	for (cx = 0; cx < pImageExportDirectory->NumberOfNames; cx++) {
		PCHAR pczFunctionName = (PCHAR)(g_dwModuleBaseAddress + pdwAddressOfNames[cx]);
		DWORD64 dwFunctionAddress = g_dwModuleBaseAddress + pdwAddressOfFunctions[pwAddressOfNameOrdinales[cx]];
		printf("   - 0x%016llx %s\n", dwFunctionAddress, pczFunctionName);
	}

	wprintf(L"[+] Parse the export directory ... OK");

	return 0x0;
}

/*F+F+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
  Function: PlLoadLibrary

  Summary:  Load a library in to the memory space of the process.
            First check if the DLL exist.
			Set the g_dwModuleBaseAddress varaible with the base address
			of the dll.

  Args:     LPCWSTR szDllName
			  Absolut path of the DLL to load.

  Returns:  BOOL
			  Return true of the DLL was successfully loaded.
-----------------------------------------------------------------F-F*/
BOOL PlLoadLibrary(LPCWSTR szDllName) {
	// Check if file exist
	DWORD dwSuccess = GetFileAttributes(szDllName);
	if (dwSuccess == INVALID_FILE_ATTRIBUTES) {
		return FALSE;
	}

	// Load the DLL 
	// HMODULE being the base address of the DLL
	g_dwModuleBaseAddress = (DWORD64)LoadLibrary(szDllName);
	if (g_dwModuleBaseAddress == 0x0) {
		return FALSE;
	}

	return TRUE;
}
