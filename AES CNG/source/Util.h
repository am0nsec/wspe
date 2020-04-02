#pragma once
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOCOMM
#define NOCOMM
#endif
#include <Windows.h>

namespace CNG {
	class Util {
		public:
		static VOID WriteSuccessMessage(std::wstring wsBuffer);
		static VOID WriteSuccessMessage(std::wstring wsBuffer, int tabs);

		static VOID WriteErrorMessage(std::wstring wsBuffer);
		static VOID WriteErrorMessage(std::wstring wsBuffer, int tabs);

		static VOID WriteInfoMessage(std::wstring wsBuffer);
		static VOID WriteInfoMessage(std::wstring wsBuffer, int tabs);

		static VOID WriteMessage(std::wstring wsBuffer);
	};
}