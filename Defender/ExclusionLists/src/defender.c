/**
* @file			defender.c
* @author		Paul L. (@am0nsec)
* @version		1.0
* @brief        Windows Defender exclusion list source.
* @details
* @link			https://github.com/am0nsec/wspe
* @copyright	This project has been released under the GNU Public License v3 license.
*/

#include <Windows.h>

#include "defender.h"

_Use_decl_annotations_
HRESULT STDMETHODCALLTYPE DfdGetAllExclusions(
	_Out_ PDEFENDER_EXCLUSION_LIST pExclusionsList
) {
	if (pExclusionsList == NULL)
		return E_INVALIDARG;

	// Open and handle to the following windows Registry key:
	// Computer\HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Exclusions
	HKEY hExclusionList = INVALID_HANDLE_VALUE;
	LSTATUS Status = RegOpenKeyA(
		HKEY_LOCAL_MACHINE,
		"SOFTWARE\\Microsoft\\Windows Defender\\Exclusions",
		&hExclusionList
	);
	if (Status != ERROR_SUCCESS || hExclusionList == INVALID_HANDLE_VALUE)
		return E_FAIL;

	// Get handle to the process heap for memory allocation
	HANDLE hHeap = GetProcessHeap();

	// Build a local copy of the final structure.
	DEFENDER_EXCLUSION_LIST ExclusionList = { 0x00 };

	// Prepare local variables
	HRESULT Result = S_OK;
	DWORD dwNumberOfValues = 0x00;

	// Get extensions
	ExclusionList.Extensions = HeapAlloc(hHeap, HEAP_ZERO_MEMORY, sizeof(DEFENDER_EXCLUSION_ENTRY));
	Result = DfdpGetExclusionEntries(
		ExclusionList.Extensions,
		"Extensions",
		DefenderExclusionExtensions,
		&hExclusionList,
		&hHeap,
		&dwNumberOfValues
	);
	if (Result != S_OK || dwNumberOfValues == 0x00) {
		HeapFree(hHeap, 0x00, ExclusionList.Extensions);
		ExclusionList.Extensions = NULL;
	}

	// Get IpAddresses
	ExclusionList.IpAddresses = HeapAlloc(hHeap, HEAP_ZERO_MEMORY, sizeof(DEFENDER_EXCLUSION_ENTRY));
	Result = DfdpGetExclusionEntries(
		ExclusionList.IpAddresses,
		"IpAddresses",
		DefenderExclusionIpAddress,
		&hExclusionList,
		&hHeap,
		&dwNumberOfValues
	);
	if (Result != S_OK || dwNumberOfValues == 0x00) {
		HeapFree(hHeap, 0x00, ExclusionList.IpAddresses);
		ExclusionList.IpAddresses = NULL;
	}

	// Get paths
	ExclusionList.Paths = HeapAlloc(hHeap, HEAP_ZERO_MEMORY, sizeof(DEFENDER_EXCLUSION_ENTRY));
	Result = DfdpGetExclusionEntries(
		ExclusionList.Paths,
		"Paths",
		DefenderExclusionPaths,
		&hExclusionList,
		&hHeap,
		&dwNumberOfValues
	);
	if (Result != S_OK || dwNumberOfValues == 0x00) {
		HeapFree(hHeap, 0x00, ExclusionList.Paths);
		ExclusionList.Paths = NULL;
	}

	// Get processes
	ExclusionList.Processes = HeapAlloc(hHeap, HEAP_ZERO_MEMORY, sizeof(DEFENDER_EXCLUSION_ENTRY));
	Result = DfdpGetExclusionEntries(
		ExclusionList.Processes,
		"Processes",
		DefenderExclusionProcesses,
		&hExclusionList,
		&hHeap,
		&dwNumberOfValues
	);
	if (Result != S_OK || dwNumberOfValues == 0x00) {
		HeapFree(hHeap, 0x00, ExclusionList.Extensions);
		ExclusionList.Extensions = NULL;
	}

	// Get temporary paths
	ExclusionList.TemporaryPaths = HeapAlloc(hHeap, HEAP_ZERO_MEMORY, sizeof(DEFENDER_EXCLUSION_ENTRY));
	Result = DfdpGetExclusionEntries(
		ExclusionList.TemporaryPaths,
		"TemporaryPaths",
		DefenderExclusionTemporaryPaths,
		&hExclusionList,
		&hHeap,
		&dwNumberOfValues
	);
	if (Result != S_OK || dwNumberOfValues == 0x00) {
		HeapFree(hHeap, 0x00, ExclusionList.TemporaryPaths);
		ExclusionList.TemporaryPaths = NULL;
	}

	// Cleanup and return data
	RegCloseKey(hExclusionList);
	*pExclusionsList = ExclusionList;
	return S_OK;
}

_Use_decl_annotations_
HRESULT STDMETHODCALLTYPE DfdpGetExclusionEntries(
	_In_  PDEFENDER_EXCLUSION_ENTRY     pExclusionEntry,
	_In_  LPCSTR                        szSubKeyName,
	_In_  CONST DEFENDER_EXCLUSION_TYPE Type,
	_In_  CONST PHKEY                   pParentKey,
	_In_  CONST PHANDLE                 phHeap,
	_Out_ PDWORD                        pdwNumberOfValues
) {
	if (pExclusionEntry == NULL
		|| szSubKeyName == NULL
		|| pParentKey == NULL
		|| *pParentKey == INVALID_HANDLE_VALUE
		|| phHeap == NULL)
		return E_INVALIDARG;

	// Open an handle to the subkey
	HKEY hSubKey = INVALID_HANDLE_VALUE;
	LSTATUS Status = RegOpenKeyA(
		*pParentKey,
		szSubKeyName,
		&hSubKey
	);
	if (Status != ERROR_SUCCESS || hSubKey == INVALID_HANDLE_VALUE)
		return E_FAIL;

	// Get all the number of values stored in the Registry key
	DWORD dwMaxValueNameLength = 0x00;

	Status = RegQueryInfoKeyA(
		hSubKey,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		pdwNumberOfValues,
		&dwMaxValueNameLength,
		NULL,
		NULL,
		NULL
	);
	if (Status != ERROR_SUCCESS) {
		RegCloseKey(hSubKey);
		return E_FAIL;
	}
	if (*pdwNumberOfValues == 0x00)
		return S_OK;
	dwMaxValueNameLength++;

	// Save previous entry
	PDEFENDER_EXCLUSION_ENTRY Blink = NULL;

	// Get all the values one by one
	for (DWORD cx = 0x00; cx < *pdwNumberOfValues; cx++) {

		// Allocate memory for a new entry
		PDEFENDER_EXCLUSION_ENTRY ExclusionEntry = NULL;
		if (cx == 0x00) {
			ExclusionEntry = pExclusionEntry;
		}
		else {
			ExclusionEntry = HeapAlloc(*phHeap, HEAP_ZERO_MEMORY, sizeof(DEFENDER_EXCLUSION_ENTRY));
		}
		ExclusionEntry->Exclusion = HeapAlloc(*phHeap, HEAP_ZERO_MEMORY, dwMaxValueNameLength);

		// Get the value name
		DWORD dwBufferSize = dwMaxValueNameLength;
		Status = RegEnumValueA(hSubKey, cx, ExclusionEntry->Exclusion, &dwBufferSize, NULL, NULL, NULL, NULL);
		if (Status != ERROR_SUCCESS) {
			HeapFree(*phHeap, 0x00, ExclusionEntry->Exclusion);
			HeapFree(*phHeap, 0x00, ExclusionEntry);
			RegCloseKey(hSubKey);
			return E_FAIL;
		}

		// Allocate memory for the double-linked list
		ExclusionEntry->Type = Type;
		ExclusionEntry->Length = dwBufferSize;

		// Create chain
		if (Blink != NULL) {
			ExclusionEntry->Blink = Blink;
			((PDEFENDER_EXCLUSION_ENTRY)ExclusionEntry->Blink)->Flink = ExclusionEntry;
		}
		Blink = ExclusionEntry;
	}

	RegCloseKey(hSubKey);
	return S_OK;














	//// Allocate memory for first entry


	//// Extract all the entries
	//HRESULT Result = DfdpGetExclusionEntries(
	//	pExclusionEntry,
	//	DefenderExclusionExtensions,
	//	&hSubKey,
	//	phHeap
	//);
	//if (Result != S_OK) {
	//	HeapFree(*phHeap, 0x00, pExclusionsList->Extensions);
	//	return E_FAIL;
	//}
	//return S_OK;
}

_Use_decl_annotations_
HRESULT STDMETHODCALLTYPE DfdpCleanup(
	_In_ PDEFENDER_EXCLUSION_LIST pExclusionsList
) {
	if (pExclusionsList == NULL)
		return E_FAIL;

	// Get handle to process heap
	HANDLE hHeap = GetProcessHeap();

	// Clean all the memory allocated
	for (DWORD cx = 0x00; cx < (sizeof(DEFENDER_EXCLUSION_LIST) / sizeof(PVOID)); cx++) {
		PDEFENDER_EXCLUSION_ENTRY Entry = *(PUINT64)((PBYTE)pExclusionsList + (8 * cx));
		while (Entry != NULL) {
			HeapFree(hHeap, 0x00, Entry->Exclusion);
			if (Entry->Blink != NULL)
				HeapFree(hHeap, 0x00, Entry->Blink);
			if (Entry->Flink == NULL) {
				HeapFree(hHeap, 0x00, Entry);
				break;
			}
			Entry = Entry->Flink;
		}
	}

	ZeroMemory(pExclusionsList, sizeof(DEFENDER_EXCLUSION_LIST));
	return S_OK;
}