/*+================================================================================================
Module Name: main.c
Author     : Paul L. (@am0nsec)
Origin     : https://github.com/am0nsec/wspe/
Copyright  : This project has been released under the GNU Public License v3 license.

Abstract:
Application entry point.

================================================================================================+*/

#include <Windows.h>

#include "interface.h"

// Macro to make the code less bloated
#define EXIT_ON_FAILURE(ex) if (!SUCCEEDED(ex)) { return EXIT_FAILURE; }

#define ADD_TABLE_ENTRY(str) { 0x00, 0x00, 0x00, 0x00, str }

VOID SortTable(
	_In_ PUBLIC_SYMBOL PublicSymbols[],
	_In_ DWORD         Elements
) {
	// Sort with segment
	for (DWORD cx = 0x00; cx < (Elements - 1); cx++) {
		for (DWORD dx = 0x00; dx < (Elements - cx - 1); dx++) {
			if (PublicSymbols[dx].dwSeg > PublicSymbols[dx + 1].dwSeg) {

				PUBLIC_SYMBOL Temp = PublicSymbols[dx];
				RtlCopyMemory(&Temp, &PublicSymbols[dx], sizeof(PUBLIC_SYMBOL));
				RtlCopyMemory(&PublicSymbols[dx], &PublicSymbols[dx + 1], sizeof(PUBLIC_SYMBOL));
				RtlCopyMemory(&PublicSymbols[dx + 1], &Temp, sizeof(PUBLIC_SYMBOL));
			}
		}
	}

	// Sort with RVA
	for (DWORD cx = 0x00; cx < (Elements - 1); cx++) {
		for (DWORD dx = 0x00; dx < (Elements - cx - 1); dx++) {
			if (PublicSymbols[dx].dwRVA > PublicSymbols[dx + 1].dwRVA) {

				PUBLIC_SYMBOL Temp = PublicSymbols[dx];
				RtlCopyMemory(&Temp, &PublicSymbols[dx], sizeof(PUBLIC_SYMBOL));
				RtlCopyMemory(&PublicSymbols[dx], &PublicSymbols[dx + 1], sizeof(PUBLIC_SYMBOL));
				RtlCopyMemory(&PublicSymbols[dx + 1], &Temp, sizeof(PUBLIC_SYMBOL));
			}
		}
	}
}

/// <summary>
/// Application Entry Point.
/// </summary>
/// <returns>Exit status code.</returns>
INT main(VOID) {
	// Banner
	wprintf(L"=================================================================\r\n");
	wprintf(L"Module Name: Microsoft Debug Interface Access (DIA) Experiments \r\n");
	wprintf(L"Author     : Paul L. (@am0nsec)                                 \r\n");
	wprintf(L"Origin     : https://github.com/am0nsec/wspe/                   \r\n\r\n");
	wprintf(L"Tested OS  : Windows 10 (20h2) - 19044.1706                     \r\n");
	wprintf(L"=================================================================\r\n\r\n");

	// Initialise COM runtime and get IDiaDataSource interface.
	wprintf(L"[*] Initialise MSDIA \r\n");
	EXIT_ON_FAILURE(DiaInitialise(L"msdia140.dll"));

	// Load the data from the PDB
	wprintf(L"[*] Open PDB from EXE: C:\\WINDOWS\\System32\\ntoskrnl.exe\r\n");
	EXIT_ON_FAILURE(DiaLoadDataFromPdb(L"C:\\WINDOWS\\System32\\ntoskrnl.exe"));

	// Parse all public symbols
	PUBLIC_SYMBOL Symbols[] = {
		// Memory Manager variables
		ADD_TABLE_ENTRY(L"MiState"),
		ADD_TABLE_ENTRY(L"MiVisibleState"),
		ADD_TABLE_ENTRY(L"MmPteBase"),
		ADD_TABLE_ENTRY(L"MmSizeOfNonPagedPoolInBytes"),
		ADD_TABLE_ENTRY(L"MmHighestUserAddress"),
		ADD_TABLE_ENTRY(L"PoolTrackTable"),
		ADD_TABLE_ENTRY(L"ExPoolTagTables"),
		ADD_TABLE_ENTRY(L"ExpPoolBlockShift"),
		ADD_TABLE_ENTRY(L"ExpSessionPoolTrackTable"),
		ADD_TABLE_ENTRY(L"ExpSessionPoolTrackTableSize"),

		// Loader variables
		ADD_TABLE_ENTRY(L"PsLoadedModuleList"),

		// Process Manager variables
		ADD_TABLE_ENTRY(L"PsActiveProcessHead"),

		// General kernel info
		ADD_TABLE_ENTRY(L"KeNumberProcessors")
	};
	EXIT_ON_FAILURE(DiaFindPublicSymbols(Symbols, _ARRAYSIZE(Symbols)));

	// Display everything to console
	SortTable(Symbols, _ARRAYSIZE(Symbols));
	
	wprintf(L"\r\n");
	wprintf(L"Found  Segment  RVA       Offset    Name\r\n");
	wprintf(L"-----  -------  ---       ------    ----\r\n");

	DWORD Found = 0x00;
	for (DWORD cx = 0x00; cx < _ARRAYSIZE(Symbols); cx++) {
		wprintf(L"%s      %04X     %08X  %08X  %s\r\n",
			Symbols[cx].dwRVA != 0x00 ? L"\033[0;32mY\033[0;37m" : L"\033[0;31mN\033[0;37m",
			Symbols[cx].dwSeg,
			Symbols[cx].dwRVA,
			Symbols[cx].dwOff,
			Symbols[cx].Name
		);
		Found += Symbols[cx].dwRVA != 0x00 ? 1 : 0;
	}

	wprintf(L"\r\n");
	wprintf(L"Found:   %i\r\n", Found);
	wprintf(L"Missing: %i\t\n", (_ARRAYSIZE(Symbols) - Found));

	// Uninitialise COM runtime and general cleanup
	DiaUninitialise();
	return EXIT_SUCCESS;
}