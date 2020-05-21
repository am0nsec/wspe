#pragma once
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOCOMM
#define NOCOMM
#endif
#include <Windows.h>
#include <iostream>
#include "Util.h"

namespace CNG {
	VOID WINAPI Util::WriteSuccessMessage(std::wstring wsBuffer) {
		std::wcout << L"[+] ";
		Util::WriteMessage(wsBuffer);
	}

	VOID WINAPI Util::WriteSuccessMessage(std::wstring wsBuffer, int tabs) {
		for (int i = 0; i <= tabs; i++)
			std::wcout << " ";
		std::wcout << L"[+] ";
		Util::WriteMessage(wsBuffer);
	}

	VOID WINAPI Util::WriteErrorMessage(std::wstring wsBuffer) {
		std::wcout << L"[-] ";
		Util::WriteMessage(wsBuffer);
	}

	VOID WINAPI Util::WriteErrorMessage(std::wstring wsBuffer, int tabs) {
		for (int i = 0; i <= tabs; i++)
			std::wcout << " ";
		std::wcout << L"[-] ";
		Util::WriteMessage(wsBuffer);
	}

	VOID WINAPI Util::WriteInfoMessage(std::wstring wsBuffer) {
		std::wcout << L"[>] ";
		Util::WriteMessage(wsBuffer);
	}

	VOID WINAPI Util::WriteInfoMessage(std::wstring wsBuffer, int tabs) {
		for (int i = 0; i <= tabs; i++) 
			std::wcout << " ";
		std::wcout << L"[>] ";
		Util::WriteMessage(wsBuffer);
	}

	VOID WINAPI Util::WriteMessage(std::wstring wsBuffer) {
		std::wcout << wsBuffer;
	}
}