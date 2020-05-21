#pragma once
#include <Windows.h>
#include <bcrypt.h>
#include <iostream>
#include <vector>

#include "nthelpers.h"
#include "AES.h"
#include "Util.h"
#include "Base64.h"

#pragma comment(lib, "Bcrypt.lib")

namespace CNG {
	AES::~AES() {
		if (this->hKeyHandle != NULL)
			::BCryptDestroyKey(this->hKeyHandle);

		if (this->hBcryptAlgHandle != NULL)
			::BCryptCloseAlgorithmProvider(this->hBcryptAlgHandle, 0);

		if (this->pbKeyObject != NULL)
			::HeapFree(::GetProcessHeap(), 0, this->pbKeyObject);

		if (this->pbIV != NULL)
			::HeapFree(::GetProcessHeap(), 0, this->pbIV);

		if (this->pbPlainText != NULL)
			::HeapFree(::GetProcessHeap(), 0, this->pbPlainText);

		if (this->pbCipherText != NULL)
			::HeapFree(::GetProcessHeap(), 0, this->pbCipherText);
	}
	AESEncrypt::~AESEncrypt() {}
	AESDecrypt::~AESDecrypt() {}

	BOOL WINAPI AES::Initialise() {
		if (this->bIsInitialised)
			return TRUE;

		NTSTATUS ntStatus = STATUS_UNSUCCESSFUL;

		CNG::Util::WriteInfoMessage(L"Call bcrypt!BCryptOpenAlgorithmProvider\n", 3);
		ntStatus = ::BCryptOpenAlgorithmProvider(&this->hBcryptAlgHandle, BCRYPT_AES_ALGORITHM, NULL, 0);
		if (!NT_SUCCESS(ntStatus)) {
			CNG::Util::WriteErrorMessage(L"First bcrypt!BCryptOpenAlgorithmProvider failed\n");
			return FALSE;
		}

		ntStatus = ::BCryptGetProperty(this->hBcryptAlgHandle, BCRYPT_OBJECT_LENGTH, (PBYTE)(&this->cbKeyObject), sizeof(DWORD), &this->cbData, 0);
		if (!NT_SUCCESS(ntStatus)) {
			CNG::Util::WriteErrorMessage(L"First bcrypt!BCryptGetProperty failed\n");
			return FALSE;
		}

		this->pbKeyObject = (PBYTE)::HeapAlloc(::GetProcessHeap(), 0, this->cbKeyObject);
		ntStatus = ::BCryptGetProperty(this->hBcryptAlgHandle, BCRYPT_BLOCK_LENGTH, (PBYTE)(&this->cbBlockLen), sizeof(DWORD), &this->cbData, 0);
		if (!NT_SUCCESS(ntStatus)) {
			CNG::Util::WriteErrorMessage(L"Second bcrypt!BCryptGetProperty failed\n");
			return FALSE;
		}

		if (this->cbBlockLen > sizeof(CNG::rgbIV))
			return FALSE;

		this->pbIV = (PBYTE)::HeapAlloc(::GetProcessHeap(), 0, this->cbBlockLen);
		::RtlCopyMemory(this->pbIV, CNG::rgbIV, this->cbBlockLen);
		ntStatus = ::BCryptSetProperty(this->hBcryptAlgHandle, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
		if (!NT_SUCCESS(ntStatus)) {
			CNG::Util::WriteErrorMessage(L"bcrypt!BCryptSetProperty failed\n");
			return FALSE;
		}

		CNG::Util::WriteInfoMessage(L"Call bcrypt!BCryptGenerateSymmetricKey\n", 3);
		ntStatus = ::BCryptGenerateSymmetricKey(this->hBcryptAlgHandle, &this->hKeyHandle, this->pbKeyObject, this->cbKeyObject, (PBYTE)CNG::rgbAES128Key, sizeof(CNG::rgbAES128Key), 0);
		if (!NT_SUCCESS(ntStatus)) {
			CNG::Util::WriteErrorMessage(L"bcrypt!BCryptGenerateSymmetricKey failed\n");
			return FALSE;
		}

		this->bIsInitialised = TRUE;
		return this->bIsInitialised;
	}

	BOOL WINAPI AESEncrypt::SetBase64StringToEncrypt(std::string sPlaintext) {
		if (!sPlaintext.empty()) {
			std::vector<uint8_t> vec = Base64::Base64Decode(sPlaintext);
			std::string tmp(vec.begin(), vec.end());

			return this->SetStringToEncrypt(tmp);
		}

		CNG::Util::WriteErrorMessage(L"Enpty string provided");
		return FALSE;
	}

	BOOL WINAPI AESEncrypt::SetStringToEncrypt(std::string sPlaintext) {
		if (!sPlaintext.empty()) {
			this->cbPlainText = (DWORD)sPlaintext.size();
			this->pbPlainText = (PBYTE)::HeapAlloc(::GetProcessHeap(), 0, this->cbPlainText);
			::RtlCopyMemory(this->pbPlainText, sPlaintext.c_str(), sPlaintext.size());

			return TRUE;
		}

		CNG::Util::WriteErrorMessage(L"Enpty string provided");
		return FALSE;
	}

	BOOL WINAPI AESDecrypt::SetStringToDecrypt(std::string sCipherText) {
		if (!sCipherText.empty()) {
			this->cbCipherText = (DWORD)sCipherText.size();
			this->pbCipherText = (PBYTE)::HeapAlloc(::GetProcessHeap(), 0, this->cbPlainText);
			::RtlCopyMemory(this->pbCipherText, sCipherText.c_str(), sCipherText.size());

			return TRUE;
		}

		CNG::Util::WriteErrorMessage(L"Enpty string provided");
		return FALSE;
	}

	BOOL WINAPI AESDecrypt::SetBase64StringToDecrypt(std::string sCipherText) {
		if (!sCipherText.empty()) {
			std::vector<uint8_t> vec = Base64::Base64Decode(sCipherText);
			std::string tmp(vec.begin(), vec.end());

			return this->SetStringToDecrypt(tmp);
		}

		CNG::Util::WriteErrorMessage(L"Enpty string provided");
		return FALSE;
	}

	BOOL WINAPI AESEncrypt::Encrypt() {
		NTSTATUS ntStatus = STATUS_UNSUCCESSFUL;

		// Check that everything was set correctly
		if (this->bAlreadyUsed)
			return FALSE;

		// Get the output buffer size to encrypt
		CNG::Util::WriteInfoMessage(L"Call bcrypt!BCryptEncrypt\n", 3);
		ntStatus = ::BCryptEncrypt(this->hKeyHandle, this->pbPlainText, this->cbPlainText, NULL, this->pbIV, this->cbBlockLen, NULL, 0, &this->cbCipherText, BCRYPT_BLOCK_PADDING);
		if (!NT_SUCCESS(ntStatus)) {
			CNG::Util::WriteErrorMessage(L"First bcrypt!BCryptEncrypt failed\n");
			return FALSE;
		}

		CNG::Util::WriteInfoMessage(L"Call bcrypt!BCryptEncrypt\n", 3);
		this->pbCipherText = (PBYTE)::HeapAlloc(::GetProcessHeap(), 0, this->cbCipherText);
		ntStatus = ::BCryptEncrypt(this->hKeyHandle, this->pbPlainText, this->cbPlainText, NULL, this->pbIV, this->cbBlockLen, this->pbCipherText, this->cbCipherText, &this->cbData, BCRYPT_BLOCK_PADDING);
		if (!NT_SUCCESS(ntStatus)) {
			CNG::Util::WriteErrorMessage(L"Second bcrypt!BCryptEncrypt failed\n");
			return FALSE;
		}

		// Destroy the key
		CNG::Util::WriteInfoMessage(L"Call bcrypt!BCryptDestroyKey\n", 3);
		ntStatus = ::BCryptDestroyKey(this->hKeyHandle);
		if (!NT_SUCCESS(ntStatus)) {
			CNG::Util::WriteErrorMessage(L"bcrypt!BCryptDestroyKey failed\n");
			return FALSE;
		}

		this->bAlreadyUsed = TRUE;
		return this->bAlreadyUsed;
	}

	BOOL WINAPI AESDecrypt::Decrypt() {
		NTSTATUS ntStatus = STATUS_UNSUCCESSFUL;

		// Check that everything was set correctly
		if (this->bAlreadyUsed)
			return FALSE;

		CNG::Util::WriteInfoMessage(L"Call bcrypt!BCryptDecrypt\n", 3);
		ntStatus = ::BCryptDecrypt(this->hKeyHandle, this->pbCipherText, this->cbCipherText, NULL, this->pbIV, this->cbBlockLen, NULL, 0, &this->cbPlainText, BCRYPT_BLOCK_PADDING);
		if (!NT_SUCCESS(ntStatus)) {
			CNG::Util::WriteErrorMessage(L"First bcrypt!BCryptDecrypt failed\n");
			return FALSE;
		}

		CNG::Util::WriteInfoMessage(L"Call bcrypt!BCryptDecrypt\n", 3);
		this->pbPlainText = (PBYTE)::HeapAlloc(::GetProcessHeap(), 0, this->cbPlainText);
		ntStatus = ::BCryptDecrypt(this->hKeyHandle, this->pbCipherText, this->cbCipherText, NULL, this->pbIV, this->cbBlockLen, this->pbPlainText, this->cbPlainText , &this->cbData, BCRYPT_BLOCK_PADDING);
		if (!NT_SUCCESS(ntStatus)) {
			CNG::Util::WriteErrorMessage(L"Second bcrypt!BCryptDecrypt failed\n");
			return FALSE;
		}

		// Destroy the key
		CNG::Util::WriteInfoMessage(L"Call bcrypt!BCryptDestroyKey\n", 3);
		ntStatus = ::BCryptDestroyKey(this->hKeyHandle);
		if (!NT_SUCCESS(ntStatus)) {
			CNG::Util::WriteErrorMessage(L"bcrypt!BCryptDestroyKey failed\n");
			return FALSE;
		}

		this->bAlreadyUsed = TRUE;
		return this->bAlreadyUsed;
	}

	std::string WINAPI AESEncrypt::GetEncryptedString() {
		std::string tmp = (char*)this->pbCipherText;
		return tmp;
	}

	std::string WINAPI AESEncrypt::GetEncryptedBase64String() {
		std::string sCipherText;
		if (this->pbCipherText)
			sCipherText.append(Base64::Base64Encode(this->pbCipherText, this->cbCipherText));

		return sCipherText;
	}

	std::string WINAPI AESDecrypt::GetDecryptedString() {
		std::string tmp = (char*)this->pbPlainText;
		return tmp;
	}

	std::string WINAPI AESDecrypt::GetDecryptedBase64String() {
		std::string sPlaintext;
		if (this->pbCipherText)
			sPlaintext.append(Base64::Base64Encode(this->pbPlainText, this->cbPlainText));

		return sPlaintext;
	}
}