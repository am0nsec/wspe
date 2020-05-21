/*+===================================================================
  File:      main.c
  Summary:   List named objects from the Windows Object Manager namespace.
  Classes:   N/A
  Functions: N/A
  Origin:    https://github.com/am0nsec/wspe/blob/master/Windows%20Objects/List%20Objects
##
  Author: Paul Laine (@am0nsec)
===================================================================+*/
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

NTSTATUS WINAPI NtOpenSymbolicLinkObject(
	_Out_ PHANDLE            LinkHandle,
	_In_  ACCESS_MASK        DesiredAccess,
	_In_  POBJECT_ATTRIBUTES ObjectAttributes
);

NTSTATUS WINAPI NtQuerySymbolicLinkObject(
	_In_      HANDLE          LinkHandle,
	_Inout_   PUNICODE_STRING LinkTarget,
	_Out_opt_ PULONG          ReturnedLength
);

/*--------------------------------------------------------------------
  Private Function
--------------------------------------------------------------------*/
NTSTATUS GetObjInformation(
	_Out_ PUNICODE_STRING pObjName,
	_Out_ PUNICODE_STRING pObjType,
	_In_  PULONG          puContext
);

NTSTATUS GetObjSymbolicLinkTarget(
	_Out_ PUNICODE_STRING pObjSymbolicLinkTarget,
	_In_  PUNICODE_STRING pObjName
);

/*--------------------------------------------------------------------
  Global Variables
--------------------------------------------------------------------*/
HANDLE g_hRootDirectory = INVALID_HANDLE_VALUE;
HANDLE g_hProcessHeap   = INVALID_HANDLE_VALUE;

INT wmain(INT argc, PWCHAR argv[]) {
	wprintf(L"--------------------------------------------------------------\n");
	wprintf(L" List named objects from the Windows Object Manager namespace\n");
	wprintf(L"           Copyright (C) Paul Laine (@am0nsec)\n");
	wprintf(L"--------------------------------------------------------------\n\n");

	/*--------------------------------------------------------------------
	  Check user input.
	--------------------------------------------------------------------*/
	if (argc == 1) {
		wprintf(L"[-] Usage: \n");
		wprintf(L"    - WindowsObjects.exe <directory> \n");
		wprintf(L"[-] Examples: \n");
		wprintf(L"    - WindowsObjects.exe \\ \n");
		wprintf(L"    - WindowsObjects.exe \\ObjectTypes \n");
		wprintf(L"    - WindowsObjects.exe \\Sessions\\1\\BaseNamedObjects \n\n");
		return 0x1;
	}

	/*--------------------------------------------------------------------
	  Initialise variables.
	--------------------------------------------------------------------*/
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	g_hProcessHeap = GetProcessHeap();

	UNICODE_STRING RootDirectory = { 0 };
	RtlInitUnicodeString(&RootDirectory, argv[1]);

	OBJECT_ATTRIBUTES ObjAttributes;
	InitializeObjectAttributes(&ObjAttributes, &RootDirectory, OBJ_CASE_INSENSITIVE, NULL, NULL,);

	status = NtOpenDirectoryObject(&g_hRootDirectory, DIRECTORY_QUERY | GENERIC_READ, &ObjAttributes);
	if (!NT_SUCCESS(status) || g_hRootDirectory == INVALID_HANDLE_VALUE) {
		wprintf(L"[-] Error invoking ntdll!NtOpenDirectoryObject (0x%08x)\n", (DWORD)status);
		return 0x1;
	}

	/*--------------------------------------------------------------------
	  Parse all objects from the directory.
	--------------------------------------------------------------------*/
	ULONG uContext = 0;
	wprintf(L" %+-25ws   %+-30ws   %ws\n\n", L"Object Type", L"Symbolic Link", L"Object Name");

	do {
		UNICODE_STRING ObjSymbolicLink = { 0, 0, NULL };
		UNICODE_STRING ObjName = { 0, 0, NULL };
		UNICODE_STRING ObjType = { 0, 0, NULL };
		
		// Get name and type of the object
		status = GetObjInformation(&ObjName, &ObjType, &uContext);
		if (!NT_SUCCESS(status))
			break;

		// Get the symbolic link target if object type is SymbolicLink
		if (wcscmp(ObjType.Buffer, L"SymbolicLink") == 0) {
			status = GetObjSymbolicLinkTarget(&ObjSymbolicLink, &ObjName);
			if (!NT_SUCCESS(status))
				break;
		}

		// Print the information to the console
		wprintf(L" %+-25ws   %+-30ws   %ws\n", ObjType.Buffer, ObjSymbolicLink.Buffer, ObjName.Buffer);

		// Remove data from the heap
		if (ObjSymbolicLink.Length != 0)
			HeapFree(g_hProcessHeap, 0, ObjSymbolicLink.Buffer);
	} while (status != STATUS_NO_MORE_ENTRIES);
	
	wprintf(L"\n\n[>] Total named objects: %d\n\n", uContext);

	// Cleanup and exit
	if (g_hRootDirectory)
		CloseHandle(g_hRootDirectory);
	return 0x0;
}

/*F+F+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
  Function: GetObjInformation
  Summary:  Get the name and the type name of the next object in the Object Manager namespace's directory.

  Args:     PUNICODE_STRING pObjName
			   - Pointer to the UNICODE_STRING that stores the name.
		    PUNICODE_STRING pObjType
		       - Pointer to the UNICODE_STRING that stores the type.
		    PULONG puContext
		       - Pointer to next element to retrieve.

  Returns:  NTSTATUS
-----------------------------------------------------------------F-F*/
NTSTATUS GetObjInformation(PUNICODE_STRING pObjName, PUNICODE_STRING pObjType, PULONG puContext) {
	POBJECT_DIRECTORY_INFORMATION pObjInformation = NULL;
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	ULONG uStructureSize = 0;

	// Get length of the structure
	status = NtQueryDirectoryObject(g_hRootDirectory, NULL, 0, TRUE, FALSE, puContext, &uStructureSize);
	if (status == STATUS_NO_MORE_ENTRIES)
		return STATUS_NO_MORE_ENTRIES;

	if (status != STATUS_BUFFER_TOO_SMALL || uStructureSize == 0) {
		wprintf(L"[-] Error invoking ntdll!NtQueryDirectoryObject (0x%08x)\n", (DWORD)status);
		return STATUS_UNSUCCESSFUL;
	}

	// Get the information about the object
	pObjInformation = HeapAlloc(g_hProcessHeap, HEAP_ZERO_MEMORY, uStructureSize);
	status = NtQueryDirectoryObject(g_hRootDirectory, pObjInformation, uStructureSize, TRUE, FALSE, puContext, NULL);
	if (!NT_SUCCESS(status)) {
		wprintf(L"[-] Error invoking ntdll!NtQueryDirectoryObject (0x%08x)\n", (DWORD)status);
		return STATUS_UNSUCCESSFUL;
	}

	*pObjName = pObjInformation->Name;
	*pObjType = pObjInformation->TypeName;
	HeapFree(g_hProcessHeap, 0, pObjInformation);

	return STATUS_SUCCESS;
}

/*F+F+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
  Function: GetObjSymbolicLinkTarget
  Summary:  Get the name to the object that the symbolic link target.

  Args:     PUNICODE_STRING pObjSymbolicLinkTarget
			   - Pointer to the UNICODE_STRING that stores the name of the target.
			PUNICODE_STRING pObjName
			   - Pointer to the UNICODE_STRING that stores the naem of the symbolic link.

  Returns:  NTSTATUS
-----------------------------------------------------------------F-F*/
NTSTATUS GetObjSymbolicLinkTarget(PUNICODE_STRING pObjSymbolicLinkTarget, PUNICODE_STRING pObjName) {
	NTSTATUS status = STATUS_UNSUCCESSFUL;

	UNICODE_STRING LinkObj;
	RtlInitUnicodeString(&LinkObj, pObjName->Buffer);

	OBJECT_ATTRIBUTES SymbolicObjAttributes;
	InitializeObjectAttributes(&SymbolicObjAttributes, &LinkObj, OBJ_CASE_INSENSITIVE, g_hRootDirectory, NULL);

	HANDLE hLinkHandle = INVALID_HANDLE_VALUE;
	status = NtOpenSymbolicLinkObject(&hLinkHandle, GENERIC_READ, &SymbolicObjAttributes);
	if (!NT_SUCCESS(status) || hLinkHandle == INVALID_HANDLE_VALUE) {
		wprintf(L"[-] Error invoking ntdll!NtOpenSymbolicLinkObject (0x%08x)\n", (DWORD)status);
		return STATUS_UNSUCCESSFUL;
	}

	UNICODE_STRING SymbolicObjName = { 0, 0, NULL };
	ULONG lSizeSymbolicObj = 0;
	status = NtQuerySymbolicLinkObject(hLinkHandle, &SymbolicObjName, &lSizeSymbolicObj);
	if (!NT_SUCCESS(status) && status != STATUS_BUFFER_TOO_SMALL) {
		wprintf(L"[-] Error invoking ntdll!NtQuerySymbolicLinkObject (0x%08x)\n", (DWORD)status);
		CloseHandle(hLinkHandle);
		return STATUS_UNSUCCESSFUL;
	}

	SymbolicObjName.Buffer = HeapAlloc(g_hProcessHeap, HEAP_ZERO_MEMORY, lSizeSymbolicObj);
	SymbolicObjName.Length = lSizeSymbolicObj;
	SymbolicObjName.MaximumLength = (USHORT)(lSizeSymbolicObj + sizeof(WCHAR));

	status = NtQuerySymbolicLinkObject(hLinkHandle, &SymbolicObjName, &lSizeSymbolicObj);
	if (!NT_SUCCESS(status)) {
		wprintf(L"[-] Error invoking ntdll!NtQuerySymbolicLinkObject (0x%08x)\n", (DWORD)status);
		CloseHandle(hLinkHandle);
		return STATUS_UNSUCCESSFUL;
	}

	*pObjSymbolicLinkTarget = SymbolicObjName;
	if (hLinkHandle)
		CloseHandle(hLinkHandle);

	return STATUS_SUCCESS;
}
