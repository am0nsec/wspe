/**
* @file			defender.h
* @author		Paul L. (@am0nsec)
* @version		1.0
* @brief        Windows Defender Exclusion List header.
* @details
* @link			https://github.com/am0nsec/wspe
* @copyright	This project has been released under the GNU Public License v3 license.
*/

#ifndef __DEFENDER_EXCLUSIONLISTS_H_GUARD__
#define __DEFENDER_EXCLUSIONLISTS_H_GUARD__

#include <Windows.h>

/**
 * @brief Windows Defender type of exclusion entry.
*/
typedef enum _DEFENDER_EXCLUSION_TYPE {
	DefenderExclusionExtensions     = 0x00,
	DefenderExclusionIpAddress      = 0x01,
	DefenderExclusionPaths          = 0x02,
	DefenderExclusionProcesses      = 0x03,
	DefenderExclusionTemporaryPaths = 0x04
} DEFENDER_EXCLUSION_TYPE;

/**
 * @brief Double-linked list for Windows Defender exclusion entry.
*/
typedef struct _DEFENDER_EXCLUSION_ENTRY {
	LPVOID                    Blink;
	LPVOID                    Flink;
	DEFENDER_EXCLUSION_TYPE   Type;
	DWORD                     Length;
	LPCSTR                    Exclusion;
} DEFENDER_EXCLUSION_ENTRY, *PDEFENDER_EXCLUSION_ENTRY;

/**
 * @brief List of Windows Defender exclusions.
*/
typedef struct _DEFENDER_EXCLUSION_LIST {
	PDEFENDER_EXCLUSION_ENTRY Extensions;
	PDEFENDER_EXCLUSION_ENTRY IpAddresses;
	PDEFENDER_EXCLUSION_ENTRY Paths;
	PDEFENDER_EXCLUSION_ENTRY Processes;
	PDEFENDER_EXCLUSION_ENTRY TemporaryPaths;
} DEFENDER_EXCLUSION_LIST, * PDEFENDER_EXCLUSION_LIST;

_Success_(return == S_OK) _Must_inspect_result_
HRESULT STDMETHODCALLTYPE DfdGetAllExclusions(
	_Out_ PDEFENDER_EXCLUSION_LIST pExclusionsList
);

_Success_(return == S_OK) _Must_inspect_result_
HRESULT STDMETHODCALLTYPE DfdpGetExclusionEntries(
	_In_  PDEFENDER_EXCLUSION_ENTRY     pExclusionEntry,
	_In_  LPCSTR                        szSubKeyName,
	_In_  CONST DEFENDER_EXCLUSION_TYPE Type,
	_In_  CONST PHKEY                   pParentKey,
	_In_  CONST PHANDLE                 phHeap,
	_Out_ PDWORD                        pdwNumberOfValues
);

_Success_(return == S_OK)
HRESULT STDMETHODCALLTYPE DfdpCleanup(
	_In_ PDEFENDER_EXCLUSION_LIST pExclusionsList
);

#endif // !__DEFENDER_EXCLUSIONLISTS_H_GUARD__
