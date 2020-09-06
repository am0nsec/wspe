/**
* @file         gacutil.h
* @data         06-09-2020
* @author       Paul Laîné (@am0nsec)
* @version      1.0
* @brief        Global Assembly Cache Utilities.
* @details
* @link         https://github.com/am0nsec/wspe
* @copyright    This project has been released under the GNU Public License v3 license.
*/
#include <Windows.h>
#include <fusion.h>

#ifndef _GACUTIL_H
#define _GACUTIL_H

//-------------------------------------------------------------------------------------------------
// Macro
//-------------------------------------------------------------------------------------------------
#ifdef _WIN64
#define FUSION_MODULE_PATH L"C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\fusion.dll"
#else
#define FUSION_MODULE_PATH L"C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\fusion.dll"
#endif // !_WIN64

//-------------------------------------------------------------------------------------------------
// Type definition
//-------------------------------------------------------------------------------------------------
typedef struct _ASSEMBLY_VERSION {
	WORD dwMajor;
	WORD dwMinor;
	WORD dwBuild;
	WORD dwRevision;
} ASSEMBLY_VERSION, * PASSEMBLY_VERSION;

typedef IAssemblyEnum* PIAssemblyEnum;
typedef PIAssemblyEnum* PPIAssemblyEnum;

typedef IAssemblyCache* PIAssemblyCache;
typedef PIAssemblyCache* PPIAssemblyCache;

typedef IAssemblyName* PIAssemblyName;
typedef PIAssemblyName* PPIAssemblyName;

//-------------------------------------------------------------------------------------------------
// Fusion function prototype
//-------------------------------------------------------------------------------------------------
typedef HRESULT(WINAPI* CreateAssemblyEnumFunc)(
	_Out_ PPIAssemblyEnum pEnum,
	_In_  IUnknown*       pUnkReserved,
	_In_  PIAssemblyName  pName,
	_In_  DWORD           dwFlags,
	_In_  LPVOID          pvReserved
);

typedef HRESULT(WINAPI* CreateAssemblyCacheFunc)(
	_Out_ IAssemblyCache** ppAsmCache,
	_In_  DWORD            dwReserved
);

//-------------------------------------------------------------------------------------------------
// Function prototype
//-------------------------------------------------------------------------------------------------
HRESULT ParseAllAssemblies(
	_In_ PPIAssemblyEnum  ppIAssemblyEnum,
	_In_ PPIAssemblyCache ppIAssemblyCache
);

HRESULT GetAssemblyName(
	_In_  PPIAssemblyName ppIAssemblyName,
	_Out_ LPWSTR*         pwszAssemblyName
);

HRESULT GetAssemblyGACPath(
	_In_  PPIAssemblyCache ppIAssemblyCache,
	_In_  LPWSTR*          pwszAssemblyName,
	_Out_ LPWSTR*          pwszAssemblyGacPath
);

HRESULT GetAssemblyVersion(
	_In_  PPIAssemblyName   ppIAssemblyName,
	_Out_ PASSEMBLY_VERSION pAssemblyVersion
);

#endif // !_GACUTIL_H
