
#include <Windows.h>
#include <stdio.h>
#include <ntsecapi.h>
#include <wincrypt.h>

#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "Secur32.lib")
#pragma comment(lib, "Crypt32.lib")

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

#define _M_PRINT_KERBEROS_TICKET_FLAGS_INFO(var, flag, str) \
	if((var & flag) != 0x00) { wprintf(L"%s", str); var = var & ~flag; }

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
/// Print unicode string
/// </summary>
/// <param name="String">The unicode string</param>
/// <param name="hProcessHeap">Handle to the process heap</param>
VOID PrintUnicodeString(
	_In_ CONST UNICODE_STRING String,
	_In_ CONST HANDLE         hProcessHeap
) {
	WCHAR* lpBuffer = HeapAlloc(hProcessHeap, HEAP_ZERO_MEMORY, String.MaximumLength + 2);
	if (lpBuffer == NULL)
		return;

	// Copy and print the buffer
	RtlCopyMemory(lpBuffer, String.Buffer, String.MaximumLength);
	wprintf(L"%ws\r\n", lpBuffer);

	// Cleanup
	HeapFree(hProcessHeap, 0x00, lpBuffer);
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

	wprintf(L"%ws", Buffer);
}

/// <summary>
/// Display Kerberos ticket information.
/// </summary>
/// <param name="TicketFlags">Ticket flags</param>
VOID PrintTicketFlags(
	_In_ CONST LONG TicketFlags
) {
	LONG Flags = TicketFlags;
	_M_PRINT_KERBEROS_TICKET_FLAGS_INFO(Flags, KERBEROS_TICKET_FLAGS_RESERVED, L"reserved ");
	_M_PRINT_KERBEROS_TICKET_FLAGS_INFO(Flags, KERBEROS_TICKET_FLAGS_FORWARDABLE, L"fowardable ");
	_M_PRINT_KERBEROS_TICKET_FLAGS_INFO(Flags, KERBEROS_TICKET_FLAGS_FORWARDED, L"forwarded ");
	_M_PRINT_KERBEROS_TICKET_FLAGS_INFO(Flags, KERBEROS_TICKET_FLAGS_PROXIABLE, L"proxiable ");
	_M_PRINT_KERBEROS_TICKET_FLAGS_INFO(Flags, KERBEROS_TICKET_FLAGS_PROXY, L"proxy ");
	_M_PRINT_KERBEROS_TICKET_FLAGS_INFO(Flags, KERBEROS_TICKET_FLAGS_MAY_POSTDATE, L"may_postdated ");
	_M_PRINT_KERBEROS_TICKET_FLAGS_INFO(Flags, KERBEROS_TICKET_FLAGS_POSTDATED, L"postdated ");
	_M_PRINT_KERBEROS_TICKET_FLAGS_INFO(Flags, KERBEROS_TICKET_FLAGS_INVALID, L"invalid ");
	_M_PRINT_KERBEROS_TICKET_FLAGS_INFO(Flags, KERBEROS_TICKET_FLAGS_RENEWABLE, L"renewable ");
	_M_PRINT_KERBEROS_TICKET_FLAGS_INFO(Flags, KERBEROS_TICKET_FLAGS_INITIAL, L"initial ");
	_M_PRINT_KERBEROS_TICKET_FLAGS_INFO(Flags, KERBEROS_TICKET_FLAGS_PRE_AUTHENT, L"pre_authent ");
	_M_PRINT_KERBEROS_TICKET_FLAGS_INFO(Flags, KERBEROS_TICKET_FLAGS_HW_AUTHENT, L"hw_authent ");
	_M_PRINT_KERBEROS_TICKET_FLAGS_INFO(Flags, KERBEROS_TICKET_FLAGS_OK_HAS_DELEGATE, L"ok_has_delegate ");
	_M_PRINT_KERBEROS_TICKET_FLAGS_INFO(Flags, KERBEROS_TICKET_FLAGS_NAME_CANONICALIZE, L"name_canonicalize ");
	_M_PRINT_KERBEROS_TICKET_FLAGS_INFO(Flags, KERBEROS_TICKET_FLAGS_NAME_RESERVED1, L"reserved1 ");
	wprintf(L"\r\n");
}

/// <summary>
/// Display kerberos ticket time.
/// </summary>
/// <param name="Prefix">Output prefix</param>
/// <param name="Time">Time</param>
VOID PrintTime(
	_In_ CONST WCHAR* Prefix,
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

/// <summary>
/// Base64 encode and print the encoded ticket.
/// </summary>
/// <param name="EncodedTicket">The raw data of the ticket.</param>
/// <param name="EncodedTicketSize">The size of the raw ticket.</param>
/// <param name="hProcessHeap">Handle to the process heap</param>
VOID PrintEncodedTicket(
	_In_ CONST PUCHAR EncodedTicket,
	_In_ CONST DWORD  EncodedTicketSize,
	_In_ CONST HANDLE hProcessHeap
) {
	// Get the size to allocate
	DWORD dwBase64Size = 0x00;
	BOOL Success = CryptBinaryToStringW(
		EncodedTicket,
		EncodedTicketSize,
		CRYPT_STRING_BASE64,
		NULL,
		&dwBase64Size
	);
	if (!Success || dwBase64Size == 0x00)
		return;

	// Allocate size
	LPWSTR lpBase64 = HeapAlloc(hProcessHeap, HEAP_ZERO_MEMORY, dwBase64Size * sizeof(WCHAR));
	if (lpBase64 == NULL)
		return;

	// Convert to base64 the data
	Success = CryptBinaryToStringW(
		EncodedTicket,
		EncodedTicketSize,
		CRYPT_STRING_BASE64,
		lpBase64,
		&dwBase64Size
	);
	if (Success)
		wprintf(L"%ws\r\n", lpBase64);

	// Cleanup
	HeapFree(hProcessHeap, 0x00, lpBase64);
}

/// <summary>
/// Entry point.
/// </summary>
/// <returns>Application status code</returns>
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
	wprintf(L"Current LogonId is %d:0x%08x\r\n\r\n",
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

	// 3. Get Kerberos TGT
	NTSTATUS PackageStatus = STATUS_SUCCESS;

	KERB_RETRIEVE_TKT_REQUEST TicketRequest = { 0x00 };
	TicketRequest.MessageType = KerbRetrieveTicketMessage;
	TicketRequest.LogonId.LowPart = 0x00;
	TicketRequest.LogonId.HighPart = 0x00;

	PKERB_RETRIEVE_TKT_RESPONSE TicketResponse = NULL;
	ULONG ulBufferSize = 0x00;

	Status = LsaCallAuthenticationPackage(
		hLsaHandle,
		AuthPackageKerberos,
		&TicketRequest,
		sizeof(KERB_RETRIEVE_TKT_REQUEST),
		&TicketResponse,
		&ulBufferSize,
		&PackageStatus
	);
	if (!NT_SUCCESS(Status)) {
		LsaDeregisterLogonProcess(hLsaHandle);
		return EXIT_FAILURE;
	}

	// 4. Print ticket infomration
	wprintf(L"Cached TGT: \r\n\r\n");
	HANDLE hProcessHeap = GetProcessHeap();

	// Service Name
	wprintf(L"ServiceName        : ");
	PrintUnicodeString(TicketResponse->Ticket.ServiceName->Names[0x00], hProcessHeap);
	// Target name
	wprintf(L"TargetName (SPN)   : ");
	PrintUnicodeString(TicketResponse->Ticket.TargetName->Names[0x00], hProcessHeap);
	// Client name
	wprintf(L"ClientName         : ");
	PrintUnicodeString(TicketResponse->Ticket.ClientName->Names[0x00], hProcessHeap);
	// Domain name
	wprintf(L"DomainName         : ");
	PrintUnicodeString(TicketResponse->Ticket.DomainName, hProcessHeap);
	// Target domain name
	wprintf(L"TargetDomainName   : ");
	PrintUnicodeString(TicketResponse->Ticket.TargetDomainName, hProcessHeap);
	// AltTargetDomainName
	wprintf(L"AltTargetDomainName: ");
	PrintUnicodeString(TicketResponse->Ticket.AltTargetDomainName, hProcessHeap);
	// Ticket Flags
	wprintf(L"Ticket Flags       :");
	wprintf(L" 0x%08x ->", TicketResponse->Ticket.TicketFlags);
	PrintTicketFlags(TicketResponse->Ticket.TicketFlags);
	// Session Key
	wprintf(L"Session Key        :");
	wprintf(L" KeyType 0x%x - ", TicketResponse->Ticket.SessionKey.KeyType);
	PrintEType(TicketResponse->Ticket.SessionKey.KeyType);
	wprintf(L"                   :");
	wprintf(L" KeyLength %d - ", TicketResponse->Ticket.SessionKey.Length);
	for (DWORD cx = 0x00; cx < TicketResponse->Ticket.SessionKey.Length; cx++) {
		printf("%02x ", (UCHAR)TicketResponse->Ticket.SessionKey.Value[cx]);
	}
	wprintf(L"\r\n");
	// StartTime
	PrintTime(L"StartTime          : ", TicketResponse->Ticket.StartTime);
	// EndTime
	PrintTime(L"EndTime            : ", TicketResponse->Ticket.EndTime);
	// RenewUntil
	PrintTime(L"RenewUntil         : ", TicketResponse->Ticket.RenewUntil);
	// EncodedTicket size
	wprintf(L"EncodedTicket      : (size: %d)\r\n", TicketResponse->Ticket.EncodedTicketSize);
	// EncodedTicket
	PrintEncodedTicket(
		TicketResponse->Ticket.EncodedTicket,
		TicketResponse->Ticket.EncodedTicketSize,
		hProcessHeap
	);

	// x. Cleanup and exit
exit:
	LsaDeregisterLogonProcess(hLsaHandle);
	return EXIT_SUCCESS;
}