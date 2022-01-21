
#include "socket.h"

/// <summary>
/// Initialise WinSOCK 2
/// </summary>
NTSTATUS SockpInitialise() {
	WSADATA WSAData = { 0x00 };
	INT Result = WSAStartup(MAKEWORD(2, 2), &WSAData);
	return (Result != 0x00) ? STATUS_UNSUCCESSFUL : STATUS_SUCCESS;
}

/// <summary>
/// Uninitialise WinSOCK 2
/// </summary>
NTSTATUS SockpUninitialise() {
	INT Result = WSACleanup();
	return (Result != 0x00) ? STATUS_UNSUCCESSFUL : STATUS_SUCCESS;
}

/// <summary>
/// Send kerberos AS-REQ to domain controller.
/// </summary>
NTSTATUS SockSendKerberosASRequest(
	_In_  LPSTR  Address,
	_In_  PBYTE  Request,
	_In_  INT32  RequestSize,
	_Out_ PBYTE* Response,
	_Out_ INT32* ResponseSize
) {
	// Initialise WinSOCK 2
	SockpInitialise();

	// Forge the required structures
	PADDRINFOA AddressInfo = NULL;
	INT Result = getaddrinfo(
		Address,
		"88",
		NULL,
		&AddressInfo
	);
	if (Result != 0x00 || AddressInfo == NULL) {
		SockpUninitialise();
		return STATUS_UNSUCCESSFUL;
	}
	
	// Create socket
	SOCKET Socket = INVALID_SOCKET;
	Socket = socket(AddressInfo->ai_family, AddressInfo->ai_socktype, AddressInfo->ai_protocol);
	if (Socket == INVALID_SOCKET) {
		SockpUninitialise();
		return STATUS_UNSUCCESSFUL;
	}

	// Connect to remote system
	Result = connect(Socket, AddressInfo->ai_addr, AddressInfo->ai_addrlen);
	if (Result == SOCKET_ERROR) {
		closesocket(Socket);
		SockpUninitialise();
		return STATUS_UNSUCCESSFUL;
	}

	// Send the size of the request first
	UCHAR Packet[0x04] = { 0x00 };
	Packet[0x00] = XLATE_UINT32(RequestSize, 0x00);
	Packet[0x01] = XLATE_UINT32(RequestSize, 0x01);
	Packet[0x02] = XLATE_UINT32(RequestSize, 0x02);
	Packet[0x03] = XLATE_UINT32(RequestSize, 0x03);
	Result = send(Socket, Packet, 0x04, 0x00);

	// Send the data now
	Result = send(Socket, Request, RequestSize, 0x00);
	if (Result == SOCKET_ERROR) {
		closesocket(Socket);
		SockpUninitialise();
		return STATUS_UNSUCCESSFUL;
	}

	// Cleanup and exit
	closesocket(Socket);
	return SockpUninitialise();
}