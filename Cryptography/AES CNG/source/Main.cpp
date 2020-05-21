#pragma once
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOCOMM
#define NOCOMM
#endif
#include <Windows.h>
#include <iostream>
#include <ntstatus.h>
#include <vector>

#include "nthelpers.h"
#include "AES.h"
#include "Util.h"

std::string EasyEncrypt(std::string sPlaintext) {
	CNG::Util::WriteInfoMessage(L"Initialising AESEncrypt object\n");
	CNG::AESEncrypt* encrypt = new CNG::AESEncrypt();
	if (encrypt->Initialise() == FALSE) {
		CNG::Util::WriteErrorMessage(L"Unable to initialise AESEncrypt module\n");
		return "";
	}

	// Encrypt the string
	CNG::Util::WriteInfoMessage(L"Encrypt the string\n");
	encrypt->SetStringToEncrypt(sPlaintext);
	if (encrypt->Encrypt() == FALSE) {
		CNG::Util::WriteErrorMessage(L"Error while encrypting the string\n");
		return "";
	}

	// Get the base64 string 
	std::string sBase64String = encrypt->GetEncryptedBase64String();

	// Cleanup
	if (encrypt)
		encrypt->~AESEncrypt();

	return sBase64String;
}

std::string EasyDecrypt(std::string sCipherText) {
	CNG::Util::WriteInfoMessage(L"Initialising AESDecrypt object\n");
	CNG::AESDecrypt* decrypt = new CNG::AESDecrypt();
	if (decrypt->Initialise() == FALSE) {
		CNG::Util::WriteErrorMessage(L"Unable to initialise AESDecrypt module\n");
		return "";
	}

	// Decrypt the string
	CNG::Util::WriteInfoMessage(L"Decrypt the string\n");
	decrypt->SetBase64StringToDecrypt(sCipherText);
	if (decrypt->Decrypt() == FALSE) {
		CNG::Util::WriteErrorMessage(L"Error while decrypting the string\n");
		return "";
	}

	// Get the decrypted string
	std::string sPlaintext = decrypt->GetDecryptedString();

	// Cleanup
	if (decrypt)
		decrypt->~AESDecrypt();

	return sPlaintext;
}

int wmain(int argc, wchar_t* argv[]) {
	// Parameters are not used
	UNREFERENCED_PARAMETER(argc);
	UNREFERENCED_PARAMETER(argv);

	CNG::Util::WriteInfoMessage(L"Windows Cryptography API Next Generation - Example\n");
	CNG::Util::WriteInfoMessage(L"Documentation: https://docs.microsoft.com/en-us/windows/win32/seccng/cng-portal\n");
	CNG::Util::WriteMessage(L"   ---------------------------------------------------------------------------------\n\n");

	std::string sPlaintext = "cum lux abest, tenebrae vincunt";

	// Encrypt
	std::string sB64CipherText = EasyEncrypt(sPlaintext);
	CNG::Util::WriteSuccessMessage(L"Base64 cipher:\n");
	std::cout << "\t" << sB64CipherText << std::endl << std::endl << std::endl;

	// Decrypt
	std::string sCipherTextDecrypted = EasyDecrypt(sB64CipherText);
	CNG::Util::WriteSuccessMessage(L"Plaintext: \n");
	std::cout << "\t" << sCipherTextDecrypted << std::endl;

	return 1;
}