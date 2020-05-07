#pragma once
#include <Windows.h>
#include <stdio.h>
#include "ntstructs.h"

#pragma comment(lib, "ntdll")

/*--------------------------------------------------------------------
  Function prototypes.
--------------------------------------------------------------------*/
VOID RtlInitUnicodeString(
	_In_ PUNICODE_STRING DestinationString,
	_In_ PCWSTR          SourceString
);

NTSTATUS WINAPI NtOpenDirectoryObject(
	_Out_ PHANDLE            DirectoryHandle,
	_In_  ACCESS_MASK        DesiredAccess,
	_In_  POBJECT_ATTRIBUTES ObjectAttributes
);
NTSTATUS WINAPI NtQueryDirectoryObject(
	_In_      HANDLE  DirectoryHandle,
	_Out_opt_ PVOID   Buffer,
	_In_      ULONG   Length,
	_In_      BOOLEAN ReturnSingleEntry,
	_In_      BOOLEAN RestartScan,
	_Inout_   PULONG  Context,
	_Out_opt_ PULONG  ReturnLength
);

BOOL OpenRootUserDirectoryObject(
	_Out_ PHANDLE hHandle,
	_In_  PWCHAR pRootDirectory
);

/*--------------------------------------------------------------------
  Global variables.
--------------------------------------------------------------------*/
UNICODE_STRING g_CurrentDirectory = { 0 };
UNICODE_STRING g_RootUsrDirectory = { 0 };
HANDLE         g_hProcessHeap     = NULL;

INT wmain(INT argc, PWCHAR argv[]) {
	wprintf(L"----------------------------------------------------\n");
	wprintf(L"    List objects from the Windows Object Manager\n");
	wprintf(L"        Copyright (C) Paul Laine (@amonsec)\n");
	wprintf(L"----------------------------------------------------\n\n");

	/*--------------------------------------------------------------------
	  Check user input.
	--------------------------------------------------------------------*/
	if (argc == 1) {
		wprintf(L"[-] Usage: \n");
		wprintf(L"    - WindowsObjects.exe <directory> \n");
		wprintf(L"    - WindowsObjects.exe \\ \n\n");
		wprintf(L"[-] Examples: \n");
		wprintf(L"    - WindowsObjects.exe \\ObjectTypes \n");
		wprintf(L"    - WindowsObjects.exe \\Sessions\\1\\BaseNamedObjects \n\n");
		return 0x1;
	}
	RtlInitUnicodeString(&g_RootUsrDirectory, argv[1]);
	RtlInitUnicodeString(&g_CurrentDirectory, argv[1]);
	g_hProcessHeap = GetProcessHeap();

	/*--------------------------------------------------------------------
	  Get a handle to the directory object.
	--------------------------------------------------------------------*/
	HANDLE hRootDirectory = NULL;
	if (!OpenRootUserDirectoryObject(&hRootDirectory, L"\\ObjectTypes")) {
		return 0x1;
	}

	/*--------------------------------------------------------------------
	  Parse all objects from the directory.
	--------------------------------------------------------------------*/
	POBJECT_DIRECTORY_INFORMATION pObjInformation = NULL;
	ULONG uStructureSize = 0;
	ULONG uContext = 0;
	NTSTATUS status;

	wprintf(L"%+-15ws %+-20ws %ws\n", L"Directory", L"TypeName", L"Name");
	do {
		// Get length of the structure
		status = NtQueryDirectoryObject(hRootDirectory, NULL, 0, TRUE, FALSE, &uContext, &uStructureSize);
		if (status == STATUS_NO_MORE_ENTRIES)
			break;
		
		if (status != STATUS_BUFFER_TOO_SMALL || uStructureSize == 0) {
			wprintf(L"[-] Error invoking ntdll!NtQueryDirectoryObject (0x%08x)\n", (DWORD)status);
			CloseHandle(hRootDirectory);
			return 0x1;
		}

		// Get the information about the object
		pObjInformation = HeapAlloc(g_hProcessHeap, HEAP_ZERO_MEMORY, uStructureSize);
		status = NtQueryDirectoryObject(hRootDirectory, pObjInformation, uStructureSize, TRUE, FALSE, &uContext, NULL);
		if (!NT_SUCCESS(status)) {
			wprintf(L"[-] Error invoking ntdll!NtQueryDirectoryObject (0x%08x)\n", (DWORD)status);
			CloseHandle(hRootDirectory);
			return 0x1;
		}

		wprintf(L"%+-15ws %+-20ws %ws\n", g_RootUsrDirectory.Buffer, pObjInformation->TypeName.Buffer, pObjInformation->Name.Buffer);

		// Cleanup
		uStructureSize = 0;
		HeapFree(g_hProcessHeap, 0, pObjInformation);
	} while (status != STATUS_NO_MORE_ENTRIES);
	
	// Cleanup and exit
	if (hRootDirectory)
		CloseHandle(hRootDirectory);
	return 0x0;
}

BOOL OpenRootUserDirectoryObject(PHANDLE pHandle) {
	OBJECT_ATTRIBUTES ObjAttributes;
	ObjAttributes.Attributes = OBJ_CASE_INSENSITIVE;
	ObjAttributes.Length = sizeof(OBJECT_ATTRIBUTES);
	ObjAttributes.ObjectName = &g_RootUsrDirectory;
	ObjAttributes.RootDirectory = NULL;
	ObjAttributes.SecurityDescriptor = NULL;
	ObjAttributes.SecurityQualityOfService = NULL;

	NTSTATUS nt = NtOpenDirectoryObject(pHandle, DIRECTORY_QUERY, &ObjAttributes);
	if (!NT_SUCCESS(nt) || pHandle == INVALID_HANDLE_VALUE) {
		wprintf(L"Error invoking ntdll!NtOpenDirectoryObject (0x%08x)\n", (DWORD64)nt);
		return FALSE;
	}

	return TRUE;
}
