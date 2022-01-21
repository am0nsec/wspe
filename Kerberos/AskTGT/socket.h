
#ifndef __SOCKET_H_GUARD__
#define __SOCKET_H_GUARD__

#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <WinSock2.h>
#include <Windows.h>
#pragma comment(lib, "WS2_32.lib")

#define STATUS_SUCCESS            0x00000000
#define STATUS_UNSUCCESSFUL       0xC0000001
#define STATUS_PRIVILEGE_NOT_HELD 0xC0000061
#define STATUS_NOT_SUPPORTED      0xC00000BB
#define STATUS_NO_TOKEN           0xC000007C

#ifndef NT_ERROR
#define NT_ERROR(Status) ((((ULONG)(Status)) >> 30) == 3)
#endif

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

#define XLATE_UINT32(disp, x) (((ULONG32)disp & ((ULONG32)0xFF << (8 *(3 - x)))) >> (8 * (3 - x)))

NTSTATUS SockSendKerberosASRequest(
	_In_  LPSTR  Address,
	_In_  PBYTE  Request,
	_In_  INT32  RequestSize,
	_Out_ PBYTE* Response,
	_Out_ INT32* ResponseSize
);

#endif // !__SOCKET_H_GUARD__
