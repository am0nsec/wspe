#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <WinSock2.h>

#include <Windows.h>
#include <stdio.h>
#include <Lm.h>
#include <DsGetDC.h>
#include <ntsecapi.h>
#include <strsafe.h>

#include "kerberos.h"

#pragma comment(lib, "WS2_32.lib")
#pragma comment(lib, "NetApi32.lib")
#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "netapi32.lib")

/// <summary>
/// Get the information related to the primary domain controller.
/// </summary>
/// <param name="ServerName">Server to query</param>
/// <param name="DomainName">Domain to query</param>
/// <param name="DCInformation">Pointer to the PDOMAIN_CONTROLLER_INFOW pointer of structure</param>
/// <returns>Whether the function executed successfully</returns>
NTSTATUS GetDomainControllerInformation(
	_In_opt_ LPCWSTR                   ServerName,
	_In_opt_ LPCWSTR                   DomainName,
	_Inout_  PDOMAIN_CONTROLLER_INFOW* DCInformation
) {
	// Get the informations
	DWORD Status = DsGetDcNameW(
		ServerName,
		DomainName,
		NULL,
		NULL,
		(DS_FORCE_REDISCOVERY | DS_IS_DNS_NAME | DS_RETURN_DNS_NAME | DS_KDC_REQUIRED),
		DCInformation
	);
	if (Status != ERROR_SUCCESS)
		return STATUS_UNSUCCESSFUL;
	
	// Fix the domain name and ip address to remove the "\\"
	SIZE_T Size1 = wcslen((*DCInformation)->DomainControllerName);
	SIZE_T Size2 = wcslen((*DCInformation)->DomainControllerAddress);

	RtlCopyMemory((*DCInformation)->DomainControllerName, (*DCInformation)->DomainControllerName + 2, Size1 - 4);
	RtlCopyMemory((*DCInformation)->DomainControllerAddress, (*DCInformation)->DomainControllerAddress + 2, Size2 - 4);
	return STATUS_SUCCESS;
}

//NTSTATUS GetEncodedSystemTimestamp(
//	_Out_ PBYTE *ppEncodedTimestamp,
//	_Out_ DWORD *pEncodedTimestampSize
//) {
//
//
//	//StringCchVPrintfW()
//	
//}

NTSTATUS CreateRawKerberosASRequest(
	_In_  PKERBEROS_AS_REQ Request,
	_Out_ LPBYTE           RawRequest,
	_Out_ DWORD            RawRequestSize
) {
	return STATUS_SUCCESS;
}


/// <summary>
/// Entry point.
/// </summary>
/// <returns>Application status code</returns>
INT main() {
	
	LPCSTR ServerName = NULL;
	LPCSTR DomainName = NULL;
	

	// 1. Get domain controller information
	NTSTATUS Status = STATUS_SUCCESS;
	PDOMAIN_CONTROLLER_INFOW DCInformation = NULL;
	Status = GetDomainControllerInformation(
		NULL,
		DomainName,
		&DCInformation
	);
	if (!NT_SUCCESS(Status))
		return EXIT_FAILURE;
	wprintf(L"[>] Domain name      : %ws\r\n", DCInformation->DomainName);
	wprintf(L"[>] Domain controller: %ws (%ws)\r\n",
		DCInformation->DomainControllerName,
		DCInformation->DomainControllerAddress
	);

	// 2. Build AS-REQ with pre-auth
	KERBEROS_AS_REQ Request = { 0x00 };
	Request.pvno = 5;
	Request.msg_type = KERBEROS_MESSAGE_TYPE_AS_REQ;

	// ENC-TIMESTAMP 
	//Request.padata[0x00].Type = KERBEROS_PDATA_TYPE_ENC_TIMESTAMP;
	
	LPSTR NtlmHash = "7FACDC498ED1680C4FD1448319A8C04F";
	DWORD NtlmHashSize = strlen(NtlmHash);
	PBYTE EncryptedTimestamp = NULL;
	DWORD EncryptedTimestampSize = 0x00;

	KerbGenerateSystemTimestampPAData(
		NtlmHash,
		NtlmHashSize,
		&EncryptedTimestamp,
		&EncryptedTimestampSize
	);





	// PAC_REQUEST
	//Request.padata[0x01].Type = KERBEROS_PDATA_TYPE_PA_PAC_REQUEST; 


	// x. Cleanup and exit
exit:
	if (DCInformation != NULL)
		NetApiBufferFree(DCInformation);
	return EXIT_SUCCESS;
}