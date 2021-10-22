/**
* @file			main.c
* @author		Paul L. (@am0nsec)
* @version		1.0
* @brief        List Windows Defender exclusions.
* @details
* @link			https://github.com/am0nsec/wspe
* @copyright	This project has been released under the GNU Public License v3 license.
*/

#include <Windows.h>
#include <stdio.h>

#include "defender.h"

/**
 * @brief Application entry point.
 * @return Application exist status.
*/
INT main() {

	// Get the complete list of exclusions
	DEFENDER_EXCLUSION_LIST ExclusionList = { 0x00 };
	HRESULT Result = DfdGetAllExclusions(&ExclusionList);
	if (Result != S_OK)
		return EXIT_FAILURE;

	// Display everything
	PDEFENDER_EXCLUSION_ENTRY ListEntry = ExclusionList.Extensions;

	printf("Type                Value\n");
	printf("---------------     -----\n");
	for (DWORD cx = 0x00; cx < (sizeof(DEFENDER_EXCLUSION_LIST) / sizeof(PVOID)); cx++) {

		// Get the correct extension type
		PDEFENDER_EXCLUSION_ENTRY Entry = *(PUINT64)((PBYTE)&ExclusionList + (8 * cx));

		while (Entry != NULL) {
			switch (Entry->Type) {
			case DefenderExclusionExtensions:
				printf("%+-20s%s\n", "Extension", Entry->Exclusion);
				break;
			case DefenderExclusionIpAddress:
				printf("%+-20s%s\n", "IpAddress", Entry->Exclusion);
				break;
			case DefenderExclusionPaths:
				printf("%+-20s%s\n", "Paths", Entry->Exclusion);
				break;
			case DefenderExclusionProcesses:
				printf("%+-20s%s\n", "Processes", Entry->Exclusion);
				break;
			case DefenderExclusionTemporaryPaths:
				printf("%+-20s%s\n", "TemporaryPaths", Entry->Exclusion);
				break;
			}
			Entry = Entry->Flink;
		}
	}

	// Cleanup and exit
	DfdpCleanup(&ExclusionList);
	return EXIT_SUCCESS;
}