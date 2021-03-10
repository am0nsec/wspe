/**
* @file        main.c
* @data        10/03/2021
* @author      Paul L. (@am0nsec)
* @version     1.0
* @brief       Outlook utility class.
* @details
* @link        https://github.com/am0nsec/wspe
* @copyright   This project has been released under the GNU Public License v3 license.
*/

#include <Windows.h>
#include <stdio.h>

#include "outlook.h"

int main() {
	// Initialise the class
	HANDLE hHeap = INVALID_HANDLE_VALUE;
	OutlookUtil* pOutlookUtil = NULL;
	if (OuCreateOutlookUtilClass(&pOutlookUtil, &hHeap) != S_OK)
		return EXIT_FAILURE;

	// Get the entries
	OutlookContactRecord* Records = NULL;
	LONG lRecordEntries = 0x00;
	EXIT_ON_ERROR(pOutlookUtil->lpVtbl.Initialise(pOutlookUtil));
	EXIT_ON_ERROR(pOutlookUtil->lpVtbl.GetGlobalAddressList(pOutlookUtil, &lRecordEntries, &Records));

	LONG cx = 0x00;
	OutlookContactRecord* src = Records;

	printf("[>] Number of contacts: %u\n", lRecordEntries);
	for (; cx < lRecordEntries; cx++) {
		OutlookContactRecord Record = { 0x00 };
		memcpy_s(&Record, sizeof(OutlookContactRecord), src++, sizeof(OutlookContactRecord));

		wprintf(L"%s %s - %s (%s)\n", Record.FirstName, Record.LastName, Record.PrimarySmtpAddress, Record.JobTitle);
	}
	HeapFree(GetProcessHeap(), 0x00, Records);

	// Cleanup
	EXIT_ON_ERROR(pOutlookUtil->lpVtbl.Uninitialise(pOutlookUtil));
	EXIT_ON_ERROR(OuFreeOutlookUtilClass(&pOutlookUtil, &hHeap));
	return EXIT_SUCCESS;
}