/*+================================================================================================
Module Name: dirutil.h
Author     : Paul L. (@am0nsec)
Origin     : https://github.com/am0nsec/wspe/
Copyright  : This project has been released under the GNU Public License v3 license.

Abstract:
Windows Directory utility code.
Used to change directory to the "PDB" folder and get the correct symbol server search path.

================================================================================================+*/

#ifndef __DIA_DIRUTIL_H_GUARD__
#define __DIA_DIRUTIL_H_GUARD__

#include <Windows.h>

_Must_inspect_result_
HRESULT ChangeDirectory(
	_In_ PWCHAR Directory,
	_In_ DWORD  Size
);

_Must_inspect_result_
PWCHAR GetSymSrvSearchPath(
	VOID
);

_Must_inspect_result_
PWCHAR GetMsdiaModulePath(
	VOID
);

_Must_inspect_result_
HRESULT ResetDirectory(
	VOID
);

#endif // !__DIA_DIRUTIL_H_GUARD__
