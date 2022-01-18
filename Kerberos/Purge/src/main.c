
#include <Windows.h>
#include <stdio.h>
#include <ntsecapi.h>

#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "Secur32.lib")

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

	// 3. Purge all tickets
	wprintf(L"\tDeleting all tickets:");

	NTSTATUS PackageStatus = STATUS_SUCCESS;

	KERB_PURGE_TKT_CACHE_REQUEST PurgeRequest = { 0x00 };
	PurgeRequest.MessageType = KerbPurgeTicketCacheMessage;
	PurgeRequest.LogonId.LowPart = 0x00;
	PurgeRequest.LogonId.HighPart = 0x00;

	PVOID PurgeResponse = NULL;
	ULONG ulBufferSize = 0x00;

	Status = LsaCallAuthenticationPackage(
		hLsaHandle,
		AuthPackageKerberos,
		&PurgeRequest,
		sizeof(KERB_PURGE_TKT_CACHE_REQUEST),
		&PurgeResponse,
		&ulBufferSize,
		&PackageStatus
	);
	if (NT_SUCCESS(Status) && NT_SUCCESS(PackageStatus))
		wprintf(L"Ticket(s) purged!\r\n");

	// x. Cleanup and exit
exit:
	LsaDeregisterLogonProcess(hLsaHandle);
	return EXIT_SUCCESS;
}