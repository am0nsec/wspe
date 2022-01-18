#include <Windows.h>
#include <stdio.h>
#include <ntsecapi.h>

#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "Secur32.lib")

#define SeTcbPrivilege    7
#define SeDebugPrivilege 20

#define STATUS_SUCCESS            0x00000000
#define STATUS_PRIVILEGE_NOT_HELD 0xC0000061
#define STATUS_NOT_SUPPORTED      0xC00000BB
#define STATUS_NO_TOKEN           0xC000007C

#ifndef NT_ERROR
#define NT_ERROR(Status) ((((ULONG)(Status)) >> 30) == 3)
#endif

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

// Kerberos ticket encryption type
#define KERBEROS_ETYPE_NULL_CS                    0
#define KERBEROS_ETYPE_RSADSI_RC4_EXPORT          -141
#define KERBEROS_ETYPE_RSADSI_RC4                 -140
#define KERBEROS_ETYPE_RSADSI_RC4_HMAC_OLD        -133
#define KERBEROS_ETYPE_DES_PLAIN                  -132
#define KERBEROS_ETYPE_RSADSI_RC4_LM              -130
#define KERBEROS_ETYPE_RSADSI_RC4_PLAIN           -129
#define KERBEROS_ETYPE_DES_CBC_CRC                1
#define KERBEROS_ETYPE_DES_CBC_MD5                3
#define KERBEROS_ETYPE_AES_128_CTS_HMAC_SHA1_96   17
#define KERBEROS_ETYPE_AES_256_CTS_HMAC_SHA1_96   18
#define KERBEROS_ETYPE_SADSI_RC4_HMAC_NT          22
#define KERBEROS_ETYPE_RSADSI_RC4_HMAC_NT_Export  23

// Kerberos ticket flags
#define KERBEROS_TICKET_FLAGS_RESERVED            0x80000000
#define KERBEROS_TICKET_FLAGS_FORWARDABLE         0x40000000
#define KERBEROS_TICKET_FLAGS_FORWARDED           0x20000000
#define KERBEROS_TICKET_FLAGS_PROXIABLE           0x10000000
#define KERBEROS_TICKET_FLAGS_PROXY               0x08000000
#define KERBEROS_TICKET_FLAGS_MAY_POSTDATE        0x04000000
#define KERBEROS_TICKET_FLAGS_POSTDATED           0x02000000
#define KERBEROS_TICKET_FLAGS_INVALID             0x01000000
#define KERBEROS_TICKET_FLAGS_RENEWABLE           0x00800000
#define KERBEROS_TICKET_FLAGS_INITIAL             0x00400000
#define KERBEROS_TICKET_FLAGS_PRE_AUTHENT         0x00200000
#define KERBEROS_TICKET_FLAGS_HW_AUTHENT          0x00100000
#define KERBEROS_TICKET_FLAGS_OK_HAS_DELEGATE     0x00040000
#define KERBEROS_TICKET_FLAGS_NAME_CANONICALIZE   0x00010000
#define KERBEROS_TICKET_FLAGS_NAME_RESERVED1      0x00000001

// Kerberos ticket cache flags
#define KERBEROS_TICKET_CACHE_FLAGS_PRIMARY                0x00000001
#define KERBEROS_TICKET_CACHE_FLAGS_DELEGATION             0x00000002
#define KERBEROS_TICKET_CACHE_FLAGS_S4U                    0x00000004
#define KERBEROS_TICKET_CACHE_FLAGS_ASC                    0x00000008
#define KERBEROS_TICKET_CACHE_FLAGS_ENC_IN_SKEY            0x00000010
#define KERBEROS_TICKET_CACHE_FLAGS_X509                   0x00000020
#define KERBEROS_TICKET_CACHE_FLAGS_FAST                   0x00000040
#define KERBEROS_TICKET_CACHE_FLAGS_COMPOUND               0x00000080
#define KERBEROS_TICKET_CACHE_FLAGS_HUB_PRIMARY            0x00000100
#define KERBEROS_TICKET_CACHE_FLAGS_DISABLE_TGT_DELEGATION 0x00000200

#define _M_PRINT_KERBEROS_TICKET_FLAGS_INFO(var, flag, str) \
	if((var & flag) != 0x00) { wprintf(L"%s", str); var = var & ~flag; }

extern NTSTATUS RtlAdjustPrivilege(
	_In_  ULONG    Privilege,
	_In_  BOOLEAN  Enable,
	_In_  BOOLEAN  CurrentThread,
	_Out_ PBOOLEAN Enabled
);

extern NTSTATUS RtlInitString(
	_Inout_ LSA_STRING* Destination,
	_In_    LPCSTR      Source
);

/// <summary>
/// Get an handle to the LSA process via untrusted connection and retrive the "Kerberos" authentication package ID.
/// </summary>
/// <param name="phLsaHandle">Pointer to the LSA handle</param>
/// <param name="pAuthenticationPackage">Pointer to the authentication package ID.</param>
/// <returns>Whether the function was successful</returns>
NTSTATUS GetLsaHandleAndPackageId(
	_Out_ PHANDLE phLsaHandle,
	_Out_ PULONG  pAuthenticationPackage
) {
	NTSTATUS Status = STATUS_SUCCESS;
	Status = LsaConnectUntrusted(phLsaHandle);
	if (NT_ERROR(Status))
		return Status;
	
	LSA_STRING PackageName = { 0x00 };
	RtlInitString(&PackageName, "Kerberos");

	return LsaLookupAuthenticationPackage(*phLsaHandle, (PLSA_STRING)&PackageName, pAuthenticationPackage);
}

/// <summary>
/// Print Kerberos encryption type.
/// </summary>
/// <param name="EncryptionType"></param>
VOID PrintEType(
	_In_ CONST LONG EncryptionType
) {
	WCHAR* Buffer = NULL;

	switch (EncryptionType) {
	case KERBEROS_ETYPE_NULL_CS:
		Buffer = L"NULL CS\r\n";
		break;
	case KERBEROS_ETYPE_RSADSI_RC4_EXPORT:
		Buffer = L"RSADSI RC4(Export)\r\n";
		break;
	case KERBEROS_ETYPE_RSADSI_RC4:
		Buffer = L"RSADSI RC4\r\n";
		break;
	case KERBEROS_ETYPE_RSADSI_RC4_HMAC_OLD:
		Buffer = L"RSADSI RC4-HMAC(Old)\r\n";
		break;
	case KERBEROS_ETYPE_DES_PLAIN:
		Buffer = L"Kerberos DES-Plain\r\n";
		break;
	case KERBEROS_ETYPE_RSADSI_RC4_LM:
		Buffer = L"RSADSI RC4-LM\r\n";
		break;
	case KERBEROS_ETYPE_RSADSI_RC4_PLAIN:
		Buffer = L"RSADSI RC4-PLAIN\r\n";
		break;
	case KERBEROS_ETYPE_DES_CBC_CRC:
		Buffer = L"Kerberos DES-CBC-CRC\r\n";
		break;
	case KERBEROS_ETYPE_DES_CBC_MD5:
		Buffer = L"Kerberos DES-CBC-MD5\r\n";
		break;
	case KERBEROS_ETYPE_AES_128_CTS_HMAC_SHA1_96:
		Buffer = L"AES-128-CTS-HMAC-SHA1-96\r\n";
		break;
	case KERBEROS_ETYPE_AES_256_CTS_HMAC_SHA1_96:
		Buffer = L"AES-256-CTS-HMAC-SHA1-96\r\n";
		break;
	case KERBEROS_ETYPE_SADSI_RC4_HMAC_NT:
		Buffer = L"RSADSI RC4-HMAC(NT)\r\n";
		break;
	case KERBEROS_ETYPE_RSADSI_RC4_HMAC_NT_Export:
		Buffer = L"RSADSI RC4-HMAC(NT)(Export)\r\n";
		break;
	default:
		break;
	}

	wprintf(L"%s", Buffer);
}

/// <summary>
/// Display Kerberos ticket information.
/// </summary>
/// <param name="TicketFlags">Ticket flags</param>
VOID PrintTicketFlags(
	_In_ CONST LONG TicketFlags
) {
	LONG Flags = TicketFlags;
	_M_PRINT_KERBEROS_TICKET_FLAGS_INFO(Flags, KERBEROS_TICKET_FLAGS_RESERVED,          L"reserved ");
	_M_PRINT_KERBEROS_TICKET_FLAGS_INFO(Flags, KERBEROS_TICKET_FLAGS_FORWARDABLE,       L"fowardable ");
	_M_PRINT_KERBEROS_TICKET_FLAGS_INFO(Flags, KERBEROS_TICKET_FLAGS_FORWARDED,         L"forwarded ");
	_M_PRINT_KERBEROS_TICKET_FLAGS_INFO(Flags, KERBEROS_TICKET_FLAGS_PROXIABLE,         L"proxiable ");
	_M_PRINT_KERBEROS_TICKET_FLAGS_INFO(Flags, KERBEROS_TICKET_FLAGS_PROXY,             L"proxy ");
	_M_PRINT_KERBEROS_TICKET_FLAGS_INFO(Flags, KERBEROS_TICKET_FLAGS_MAY_POSTDATE,      L"may_postdated ");
	_M_PRINT_KERBEROS_TICKET_FLAGS_INFO(Flags, KERBEROS_TICKET_FLAGS_POSTDATED,         L"postdated ");
	_M_PRINT_KERBEROS_TICKET_FLAGS_INFO(Flags, KERBEROS_TICKET_FLAGS_INVALID,           L"invalid ");
	_M_PRINT_KERBEROS_TICKET_FLAGS_INFO(Flags, KERBEROS_TICKET_FLAGS_RENEWABLE,         L"renewable ");
	_M_PRINT_KERBEROS_TICKET_FLAGS_INFO(Flags, KERBEROS_TICKET_FLAGS_INITIAL,           L"initial ");
	_M_PRINT_KERBEROS_TICKET_FLAGS_INFO(Flags, KERBEROS_TICKET_FLAGS_PRE_AUTHENT,       L"pre_authent ");
	_M_PRINT_KERBEROS_TICKET_FLAGS_INFO(Flags, KERBEROS_TICKET_FLAGS_HW_AUTHENT,        L"hw_authent ");
	_M_PRINT_KERBEROS_TICKET_FLAGS_INFO(Flags, KERBEROS_TICKET_FLAGS_OK_HAS_DELEGATE,   L"ok_has_delegate ");
	_M_PRINT_KERBEROS_TICKET_FLAGS_INFO(Flags, KERBEROS_TICKET_FLAGS_NAME_CANONICALIZE, L"name_canonicalize ");
	_M_PRINT_KERBEROS_TICKET_FLAGS_INFO(Flags, KERBEROS_TICKET_FLAGS_NAME_RESERVED1,    L"reserved1 ");
	printf("\r\n");
}

/// <summary>
/// Display Kerberos ticket cache information.
/// </summary>
/// <param name="CacheFlags">Cache flags</param>
VOID PrintCacheFlags(
	_In_ CONST ULONG CacheFlags
) {
	ULONG Flags = CacheFlags;
	_M_PRINT_KERBEROS_TICKET_FLAGS_INFO(Flags, KERBEROS_TICKET_CACHE_FLAGS_PRIMARY,                L"PRIMARY ");
	_M_PRINT_KERBEROS_TICKET_FLAGS_INFO(Flags, KERBEROS_TICKET_CACHE_FLAGS_DELEGATION,             L"DELEGATION ");
	_M_PRINT_KERBEROS_TICKET_FLAGS_INFO(Flags, KERBEROS_TICKET_CACHE_FLAGS_S4U,                    L"S4U ");
	_M_PRINT_KERBEROS_TICKET_FLAGS_INFO(Flags, KERBEROS_TICKET_CACHE_FLAGS_ASC,                    L"ASC ");
	_M_PRINT_KERBEROS_TICKET_FLAGS_INFO(Flags, KERBEROS_TICKET_CACHE_FLAGS_ENC_IN_SKEY,            L"ENC-IN-SKEY ");
	_M_PRINT_KERBEROS_TICKET_FLAGS_INFO(Flags, KERBEROS_TICKET_CACHE_FLAGS_X509,                   L"X509 ");
	_M_PRINT_KERBEROS_TICKET_FLAGS_INFO(Flags, KERBEROS_TICKET_CACHE_FLAGS_FAST,                   L"FAST ");
	_M_PRINT_KERBEROS_TICKET_FLAGS_INFO(Flags, KERBEROS_TICKET_CACHE_FLAGS_COMPOUND,               L"COMPOUND ");
	_M_PRINT_KERBEROS_TICKET_FLAGS_INFO(Flags, KERBEROS_TICKET_CACHE_FLAGS_HUB_PRIMARY,            L"HUB-PRINARY ");
	_M_PRINT_KERBEROS_TICKET_FLAGS_INFO(Flags, KERBEROS_TICKET_CACHE_FLAGS_DISABLE_TGT_DELEGATION, L"DISABLE-TGT-DELEGATION ");
	printf("\r\n");
}

/// <summary>
/// Display kerberos ticket time.
/// </summary>
/// <param name="Prefix">Output prefix</param>
/// <param name="Time">Time</param>
VOID PrintTime(
	_In_ CONST WCHAR*        Prefix,
	_In_ CONST LARGE_INTEGER Time
) {
	FILETIME LocalFileTime = { 0x00 };
	FileTimeToLocalFileTime(&Time.QuadPart, &LocalFileTime);

	SYSTEMTIME SystemTime = { 0x00 };
	FileTimeToSystemTime(&LocalFileTime, &SystemTime);

	wprintf(L"%s", Prefix);
	wprintf(L"%ld/%ld/%ld %ld:%2.2ld:%2.2ld (local)\r\n",
		SystemTime.wMonth,
		SystemTime.wDay,
		SystemTime.wYear,
		SystemTime.wHour,
		SystemTime.wMinute,
		SystemTime.wSecond
	);
}

VOID ShowTicket3(
	_In_ CONST PKERB_QUERY_TKT_CACHE_EX3_RESPONSE Response
) {
	printf("Cached Tickets: (%d)\n\n", Response->CountOfTickets);
	HANDLE hProcessHeap = GetProcessHeap();

	for (DWORD cx = 0x00; cx < Response->CountOfTickets; cx++) {
		KERB_TICKET_CACHE_INFO_EX3 Ticket = Response->Tickets[cx];

		WCHAR* ClientName = HeapAlloc(hProcessHeap, HEAP_ZERO_MEMORY, Ticket.ClientName.MaximumLength + 2);
		WCHAR* ClientRealm = HeapAlloc(hProcessHeap, HEAP_ZERO_MEMORY, Ticket.ClientRealm.MaximumLength + 2);
		WCHAR* ServerName = HeapAlloc(hProcessHeap, HEAP_ZERO_MEMORY, Ticket.ServerName.MaximumLength + 2);
		WCHAR* ServerRealm = HeapAlloc(hProcessHeap, HEAP_ZERO_MEMORY, Ticket.ServerRealm.MaximumLength + 2);

		RtlCopyMemory(ClientName, Ticket.ClientName.Buffer, Ticket.ClientName.MaximumLength);
		RtlCopyMemory(ClientRealm, Ticket.ClientRealm.Buffer, Ticket.ClientRealm.MaximumLength);
		RtlCopyMemory(ServerName, Ticket.ServerName.Buffer, Ticket.ServerName.MaximumLength);
		RtlCopyMemory(ServerRealm, Ticket.ServerRealm.Buffer, Ticket.ServerRealm.MaximumLength);

		// The ID of the cached ticket
		wprintf(L"#%d>", cx);

		// Name of the client and server
		wprintf(L"\tClient: %ws @ %ws\n", ClientName, ClientRealm);
		wprintf(L"\tServer: %ws @ %ws\n", ServerName, ServerRealm);

		// Encryption type of the ticket
		wprintf(L"\tKerbTicket Encryption Type: ");
		PrintEType(Ticket.EncryptionType);

		// Ticket flags and infomration
		wprintf(L"\tTicket Flags: 0x%08x -> ", Ticket.TicketFlags);
		PrintTicketFlags(Ticket.TicketFlags);

		// Timestamps
		PrintTime(L"\tStart Time: ", Ticket.StartTime);
		PrintTime(L"\tEnd Time:   ", Ticket.EndTime);
		PrintTime(L"\tRenew Time: ", Ticket.RenewTime);

		// Session encryption type
		printf("\tSession Key Type: ");
		PrintEType(Ticket.SessionKeyType);

		// Ticket cache flags
		wprintf(L"\tCache Flags: 0x%08x -> ", Ticket.CacheFlags);
		PrintCacheFlags(Ticket.CacheFlags);

		// KDC that provided the ticket
		WCHAR* KdcCalled = HeapAlloc(hProcessHeap, HEAP_ZERO_MEMORY, Ticket.KdcCalled.MaximumLength + 2);
		RtlCopyMemory(KdcCalled, Ticket.KdcCalled.Buffer, Ticket.KdcCalled.MaximumLength);
		wprintf(L"\tKdc Called: %ws\n\n", KdcCalled);

		// Cleanup
		if (ClientName != NULL)
			HeapFree(hProcessHeap, 0x00, ClientName);
		if (ClientRealm != NULL)
			HeapFree(hProcessHeap, 0x00, ClientRealm);
		if (ServerName != NULL)
			HeapFree(hProcessHeap, 0x00, ServerName);
		if (ServerRealm != NULL)
			HeapFree(hProcessHeap, 0x00, ServerRealm);
		if (KdcCalled != NULL)
			HeapFree(hProcessHeap, 0x00, KdcCalled);
	}
}

VOID ShowTicket2(
	_In_ CONST PKERB_QUERY_TKT_CACHE_EX2_RESPONSE Response
) {
	// List all the tickets
	printf("Cached Tickets: (%d)\n\n", Response->CountOfTickets);
	HANDLE hProcessHeap = GetProcessHeap();

	for (DWORD cx = 0x00; cx < Response->CountOfTickets; cx++) {
		KERB_TICKET_CACHE_INFO_EX2 Ticket = Response->Tickets[cx];

		WCHAR* ClientName = HeapAlloc(hProcessHeap, HEAP_ZERO_MEMORY, Ticket.ClientName.MaximumLength + 2);
		WCHAR* ClientRealm = HeapAlloc(hProcessHeap, HEAP_ZERO_MEMORY, Ticket.ClientRealm.MaximumLength + 2);
		WCHAR* ServerName = HeapAlloc(hProcessHeap, HEAP_ZERO_MEMORY, Ticket.ServerName.MaximumLength + 2);
		WCHAR* ServerRealm = HeapAlloc(hProcessHeap, HEAP_ZERO_MEMORY, Ticket.ServerRealm.MaximumLength + 2);

		RtlCopyMemory(ClientName, Ticket.ClientName.Buffer, Ticket.ClientName.MaximumLength);
		RtlCopyMemory(ClientRealm, Ticket.ClientRealm.Buffer, Ticket.ClientRealm.MaximumLength);
		RtlCopyMemory(ServerName, Ticket.ServerName.Buffer, Ticket.ServerName.MaximumLength);
		RtlCopyMemory(ServerRealm, Ticket.ServerRealm.Buffer, Ticket.ServerRealm.MaximumLength);

		// The ID of the cached ticket
		wprintf(L"#%d>", cx);

		// Name of the client and server
		wprintf(L"\tClient: %ws @ %ws\n", ClientName, ClientRealm);
		wprintf(L"\tServer: %ws @ %ws\n", ServerName, ServerRealm);

		// Encryption type of the ticket
		wprintf(L"\tKerbTicket Encryption Type: ");
		PrintEType(Ticket.EncryptionType);

		// Ticket flags and infomration
		wprintf(L"\tTicket Flags: 0x%08x -> ", Ticket.TicketFlags);
		PrintTicketFlags(Ticket.TicketFlags);

		// Timestamps
		PrintTime(L"\tStart Time: ", Ticket.StartTime);
		PrintTime(L"\tEnd Time:   ", Ticket.EndTime);
		PrintTime(L"\tRenew Time: ", Ticket.RenewTime);

		// Session encryption type
		printf("\tSession Key Type: ");
		PrintEType(Ticket.SessionKeyType);

		// Cleanup
		if (ClientName != NULL)
			HeapFree(hProcessHeap, 0x00, ClientName);
		if (ClientRealm != NULL)
			HeapFree(hProcessHeap, 0x00, ClientRealm);
		if (ServerName != NULL)
			HeapFree(hProcessHeap, 0x00, ServerName);
		if (ServerRealm != NULL)
			HeapFree(hProcessHeap, 0x00, ServerRealm);
	}
}

VOID ShowTicket1(
	_In_ CONST PKERB_QUERY_TKT_CACHE_EX_RESPONSE Response
) {
	// List all the tickets
	printf("Cached Tickets: (%d)\n\n", Response->CountOfTickets);
	HANDLE hProcessHeap = GetProcessHeap();

	for (DWORD cx = 0x00; cx < Response->CountOfTickets; cx++) {
		KERB_TICKET_CACHE_INFO_EX Ticket = Response->Tickets[cx];

		WCHAR* ClientName = HeapAlloc(hProcessHeap, HEAP_ZERO_MEMORY, Ticket.ClientName.MaximumLength + 2);
		WCHAR* ClientRealm = HeapAlloc(hProcessHeap, HEAP_ZERO_MEMORY, Ticket.ClientRealm.MaximumLength + 2);
		WCHAR* ServerName = HeapAlloc(hProcessHeap, HEAP_ZERO_MEMORY, Ticket.ServerName.MaximumLength + 2);
		WCHAR* ServerRealm = HeapAlloc(hProcessHeap, HEAP_ZERO_MEMORY, Ticket.ServerRealm.MaximumLength + 2);

		RtlCopyMemory(ClientName, Ticket.ClientName.Buffer, Ticket.ClientName.MaximumLength);
		RtlCopyMemory(ClientRealm, Ticket.ClientRealm.Buffer, Ticket.ClientRealm.MaximumLength);
		RtlCopyMemory(ServerName, Ticket.ServerName.Buffer, Ticket.ServerName.MaximumLength);
		RtlCopyMemory(ServerRealm, Ticket.ServerRealm.Buffer, Ticket.ServerRealm.MaximumLength);

		// The ID of the cached ticket
		wprintf(L"#%d>", cx);

		// Name of the client and server
		wprintf(L"\tClient: %ws @ %ws\n", ClientName, ClientRealm);
		wprintf(L"\tServer: %ws @ %ws\n", ServerName, ServerRealm);

		// Encryption type of the ticket
		wprintf(L"\tKerbTicket Encryption Type: ");
		PrintEType(Ticket.EncryptionType);

		// Ticket flags and infomration
		wprintf(L"\tTicket Flags: 0x%08x -> ", Ticket.TicketFlags);
		PrintTicketFlags(Ticket.TicketFlags);

		// Timestamps
		PrintTime(L"\tStart Time: ", Ticket.StartTime);
		PrintTime(L"\tEnd Time:   ", Ticket.EndTime);
		PrintTime(L"\tRenew Time: ", Ticket.RenewTime);

		// Cleanup
		if (ClientName != NULL)
			HeapFree(hProcessHeap, 0x00, ClientName);
		if (ClientRealm != NULL)
			HeapFree(hProcessHeap, 0x00, ClientRealm);
		if (ServerName != NULL)
			HeapFree(hProcessHeap, 0x00, ServerName);
		if (ServerRealm != NULL)
			HeapFree(hProcessHeap, 0x00, ServerRealm);
	}
}

INT main() {

	// 1. Get LUID informaiton
	HANDLE hProcessHandle = GetCurrentProcess();
	HANDLE hTokenHandle = INVALID_HANDLE_VALUE;
	BOOL Result = OpenProcessToken(hProcessHandle, 0x2000000u, &hTokenHandle);

	TOKEN_STATISTICS Statistics = { 0x00 };
	DWORD dwReturnedLength = 0x00;
	Result = GetTokenInformation(hTokenHandle, TokenStatistics, &Statistics, sizeof(TOKEN_STATISTICS), &dwReturnedLength);
	if (!Result) {
		CloseHandle(hTokenHandle);
		return EXIT_FAILURE;
	}
	wprintf(L"Current LogonId is %d:0x%08x\n",
		Statistics.ModifiedId.HighPart,
		Statistics.ModifiedId.LowPart
	);
	CloseHandle(hTokenHandle);

	// 2. Connect to LSA and get the package ID
	NTSTATUS Status = STATUS_SUCCESS;
	HANDLE hLsaHandle = INVALID_HANDLE_VALUE;
	ULONG AuthPackageKerberos = 0x00;

	Status = GetLsaHandleAndPackageId(&hLsaHandle, &AuthPackageKerberos);
	if (NT_ERROR(Status))
		return EXIT_FAILURE;

	// 3. Get the tickets
	NTSTATUS PackageStatus = STATUS_SUCCESS;
	ULONG ulBufferSize = 0x00;

	LPVOID CacheResponse = NULL;
	KERB_QUERY_TKT_CACHE_REQUEST CacheRequest = { 0x00 };
	CacheRequest.MessageType = KerbQueryTicketCacheEx3Message;
	CacheRequest.LogonId.LowPart = 0x00;
	CacheRequest.LogonId.HighPart = 0x00;

	Status = LsaCallAuthenticationPackage(
		hLsaHandle,
		AuthPackageKerberos,
		&CacheRequest,
		sizeof(KERB_QUERY_TKT_CACHE_REQUEST),
		&CacheResponse,
		&ulBufferSize,
		&PackageStatus
	);
	if (Status == STATUS_NOT_SUPPORTED) {
		CacheRequest.MessageType = KerbQueryTicketCacheEx2Message;
		Status = LsaCallAuthenticationPackage(
			hLsaHandle,
			AuthPackageKerberos,
			&CacheRequest,
			sizeof(KERB_QUERY_TKT_CACHE_REQUEST),
			&CacheResponse,
			&ulBufferSize,
			&PackageStatus
		);

		if (Status == STATUS_NOT_SUPPORTED) {
			CacheRequest.MessageType = KerbQueryTicketCacheExMessage;
			Status = LsaCallAuthenticationPackage(
				hLsaHandle,
				AuthPackageKerberos,
				&CacheRequest,
				sizeof(KERB_QUERY_TKT_CACHE_REQUEST),
				&CacheResponse,
				&ulBufferSize,
				&PackageStatus
			);
			if (!NT_SUCCESS(Status))
				return EXIT_FAILURE;
			else
				ShowTicket1(CacheResponse);
		}
		else {
			ShowTicket2(CacheResponse);
		}
	}
	else {
		ShowTicket3(CacheResponse);
	}

	// x. Cleanup and exit
exit:
	if (CacheResponse != NULL)
		LsaFreeReturnBuffer(CacheResponse);
	LsaDeregisterLogonProcess(hLsaHandle);
	return EXIT_SUCCESS;
}