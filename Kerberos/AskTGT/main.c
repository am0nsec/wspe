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
	_In_opt_ LPCSTR                    ServerName,
	_In_opt_ LPCSTR                    DomainName,
	_Inout_  PDOMAIN_CONTROLLER_INFOA* DCInformation
) {
	// Get the informations
	DWORD Status = DsGetDcNameA(
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
	SIZE_T Size1 = strlen((*DCInformation)->DomainControllerName);
	SIZE_T Size2 = strlen((*DCInformation)->DomainControllerAddress);

	RtlCopyMemory((*DCInformation)->DomainControllerName, (*DCInformation)->DomainControllerName + 2, Size1 - 2);
	RtlCopyMemory((*DCInformation)->DomainControllerAddress, (*DCInformation)->DomainControllerAddress + 2, Size2 - 2);
	return STATUS_SUCCESS;
}

NTSTATUS GenerateASRequest(
	_In_ PCSTR Key,
	_In_ DWORD KeySize
) {
	// 1. PVNOP and MSG-TYPE
	ASN_ELEMENT Pvno = { 0x00 };
	ASN_ELEMENT MessageType = { 0x00 };
	KerbGeneratePvnoAndType(&Pvno, &MessageType);

	// 2 Generate and encrypt the timestamp
	ASN_ELEMENT EncryptedData = { 0x00 };
	KerbGenerateEncryptedData(Key, KeySize, &EncryptedData);

	// 3 Generate the PAC element
	ASN_ELEMENT Pac = { 0x00 };
	KerbGeneratePac(&Pac);

	// 4 Generate REQ-BODY



	// Exit
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
	PDOMAIN_CONTROLLER_INFOA DCInformation = NULL;
	Status = GetDomainControllerInformation(
		NULL,
		DomainName,
		&DCInformation
	);
	if (!NT_SUCCESS(Status))
		return EXIT_FAILURE;
	printf("[>] Domain name      : %s\r\n", DCInformation->DomainName);
	printf("[>] Domain controller: %s (%s)\r\n",
		DCInformation->DomainControllerName,
		DCInformation->DomainControllerAddress
	);

	// 2. Build AS-REQ with pre-auth
	LPSTR NtlmHash = "7FACDC498ED1680C4FD1448319A8C04F";
	DWORD NtlmHashSize = strlen(NtlmHash);
	GenerateASRequest(NtlmHash, NtlmHashSize);


	// x. Cleanup and exit
exit:
	if (DCInformation != NULL)
		NetApiBufferFree(DCInformation);
	return EXIT_SUCCESS;
}