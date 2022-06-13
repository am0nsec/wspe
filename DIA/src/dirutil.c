/*+================================================================================================
Module Name: dirutil.c
Author     : Paul L. (@am0nsec)
Origin     : https://github.com/am0nsec/wspe/
Copyright  : This project has been released under the GNU Public License v3 license.

Abstract:
Windows Directory utility code.
Used to change directory to the "PDB" folder and get the correct symbol server search path.

================================================================================================+*/

#include <Windows.h>
#include <strsafe.h>

#include "dirutil.h"

// Directory before changing.
PWCHAR g_DefaultDirectory = NULL;

// Directory after changing.
PWCHAR g_NewDirectory = NULL;

// The symbol server search path.
PWCHAR g_SymSrvSearchPath = NULL;

// Path to the msdiaXXX.dll module.
PWCHAR g_ModulePath = NULL;

_Use_decl_annotations_
HRESULT ChangeDirectory(
	_In_ PWCHAR Directory,
	_In_ DWORD  Size
) {

	// Get the current path
	DWORD dwCurrentDirectory = GetCurrentDirectoryW(0x00, NULL);
	DWORD dwBuffer = 0x100;
	while (dwCurrentDirectory > dwBuffer)
		dwBuffer += 0x100;

	// Allocate memory for the full current path
	g_DefaultDirectory = calloc(1, dwBuffer);
	if (g_DefaultDirectory == NULL)
		return E_OUTOFMEMORY;
	GetCurrentDirectoryW(dwBuffer, g_DefaultDirectory);

	// Allocate memory for the new path
	g_NewDirectory = calloc(1, dwBuffer);
	if (g_NewDirectory == NULL) {
		free(g_DefaultDirectory);
		g_DefaultDirectory = NULL;

		return E_FAIL;
	}

	// Make sure we can build the path
	if (FAILED(StringCbPrintfW(g_NewDirectory, dwBuffer, L"%s\\%s\\\0", g_DefaultDirectory, Directory))) {
		free(g_NewDirectory);
		free(g_DefaultDirectory);

		g_NewDirectory = NULL;
		g_DefaultDirectory = NULL;

		return E_FAIL;
	}

	// Set the path
	if (!SetCurrentDirectoryW(g_NewDirectory)) {
		free(g_NewDirectory);
		free(g_DefaultDirectory);

		g_NewDirectory = NULL;
		g_DefaultDirectory = NULL;

		return E_FAIL;
	}
	
	return S_OK;
}


_Use_decl_annotations_
PWCHAR GetSymSrvSearchPath(
	VOID
) {
	if (g_SymSrvSearchPath != NULL)
		return g_SymSrvSearchPath;

	// Local Stack Variables
	CONST PWCHAR Sym = L"symsrv";
	CONST PWCHAR Dll = L"symsrv.dll";
	CONST PWCHAR Web = L"https://msdl.microsoft.com/download/symbols";

	// Calculate the size of the buffer to allocate
	DWORD dwBuffer = 0x100;
	DWORD dwSize   = lstrlenW(Sym) + lstrlenW(Dll) + lstrlenW(Web) + (sizeof(WCHAR) * 4) + lstrlenW(g_NewDirectory);
	while (dwBuffer < dwSize)
		dwBuffer += 0x100;

	g_SymSrvSearchPath = calloc(1, dwBuffer);
	if (g_SymSrvSearchPath == NULL)
		return NULL;

	// Assemble the whole strign now
	HRESULT Result = StringCbPrintfW(
		g_SymSrvSearchPath,
		dwBuffer,
		L"%s*%s*%s*%s\0",
		Sym,
		Dll,
		g_NewDirectory,
		Web
	);
	if (FAILED(Result)) {
		free(g_SymSrvSearchPath);
		g_SymSrvSearchPath = NULL;
	}

	// Path value by reference
	return g_SymSrvSearchPath;
}


PWCHAR GetMsdiaModulePath(
	VOID
) {
	// Get current directory
	DWORD dwCurrentDirectory = GetCurrentDirectoryW(0x00, NULL);
	DWORD dwBuffer = 0x100;
	while (dwCurrentDirectory > dwBuffer)
		dwBuffer += 0x100;

	// Allocate memory for the current path
	PWCHAR CurrentDirectory = calloc(1, dwBuffer);
	if (CurrentDirectory == NULL)
		return E_OUTOFMEMORY;
	GetCurrentDirectoryW(dwBuffer, CurrentDirectory);

	// Calculate final size
	CONST PWCHAR Dir = L"msdia";
	CONST PWCHAR Dll = L"msdia140.dll";

	DWORD dwSize = lstrlenW(Dir) + lstrlenW(Dll) + (sizeof(WCHAR) * 4) + dwCurrentDirectory;
	while (dwBuffer < dwSize)
		dwBuffer += 0x100;

	// Assemble the path
	g_ModulePath = calloc(1, dwBuffer);
	if (g_ModulePath == NULL)
		return NULL;

	// Assemble the whole strign now
	HRESULT Result = StringCbPrintfW(
		g_ModulePath,
		dwBuffer,
		L"%s\\%s\\%s\0",
		CurrentDirectory,
		Dir,
		Dll
	);
	if (FAILED(Result)) {
		free(g_ModulePath);
		g_ModulePath = NULL;
	}

	// Path value by reference
	return g_ModulePath;
}


_Use_decl_annotations_
HRESULT ResetDirectory(
	VOID
) {
	// Change directory
	HRESULT Result = S_OK;
	if (g_DefaultDirectory != NULL)
		Result = SetCurrentDirectoryW(g_DefaultDirectory) == TRUE ? S_OK : E_FAIL;

	// Free memory
	if (g_DefaultDirectory != NULL) {
		free(g_DefaultDirectory);
		g_DefaultDirectory = NULL;
	}
	if (g_SymSrvSearchPath != NULL) {
		free(g_SymSrvSearchPath);
		g_SymSrvSearchPath = NULL;
	}
	if (g_NewDirectory != NULL) {
		free(g_NewDirectory);
		g_NewDirectory = NULL;
	}
	if (g_ModulePath != NULL) {
		free(g_ModulePath);
		g_ModulePath = NULL;
	}

	return Result;
}
