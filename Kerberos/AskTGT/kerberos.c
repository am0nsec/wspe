
#include <Windows.h>
#include <strsafe.h>
#include "kerberos.h"

/// <summary>
/// Format system time in "%ld%02ld%02ld%02ld%02ld%02ldZ" format.
/// </summary>
NTSTATUS KerbpFormatTimestamp(
	_Out_ CHAR** pszBuffer,
	_In_  CONST DWORD dwBufferSize,
	_In_  CONST CHAR* Format,
	_In_  ...
) {
	va_list ArgumentList;
	va_start(ArgumentList, Format);

	INT BytesWritten = _vsnprintf(*pszBuffer, dwBufferSize, Format, ArgumentList);
	if (BytesWritten < 0x00) {
		return STATUS_UNSUCCESSFUL;
	}
	return STATUS_SUCCESS;
}


/// <summary>
/// Get the length associated with an ASN.1 element tag
/// </summary>
INT32 KerbpGetAsnTagLength(
	_In_ INT32 Tag
) {
	if (Tag <= 0x1F)
		return 1;

	int cx = 1;
	while (Tag > 0) {
		cx++;
		Tag >>= 7;
	}
	return cx;
}

/// <summary>
/// Get the lenght of the encoded length.
/// </summary>
INT32 KerbpGetAsnLengthLenght(
	_In_ INT32 Length
) {
	if (Length < 0x80) {
		return 0x01;
	}

	INT32 cx = 1;
	while (Length > 0x00) {
		cx++;
		Length >>= 8;
	}
	return cx;
}

/// <summary>
/// Get the lenght of the object once encoded.
/// </summary>
INT32 KerbpAsnGetEffectiveEncodedLength(
	_In_ ASN_ELEMENT* pElement
) {
	if (pElement->ObjectLength < 0x00) {
		INT32 Result = KerbpAsnGetEffectiveValueLenght(pElement);
		pElement->ObjectLength = Result
			+ KerbpGetAsnLengthLenght(Result)
			+ KerbpGetAsnTagLength(pElement->TagValue);
	}
	return pElement->ObjectLength;
}

/// <summary>
/// The lenght of the value held by the element. If constructed object will sum
/// the lenght of all the sub-elements.
/// </summary>
INT32 KerbpAsnGetEffectiveValueLenght(
	_In_ ASN_ELEMENT* pElement
) {
	if (pElement->ValueLength < 0x00) {
		// Constructed element.
		if (pElement->SubElements != 0x00) {
			pElement->ValueLength = 0x00;
			for (DWORD cx = 0x00; cx < pElement->SubElements; cx++) {
				pElement->ValueLength += KerbpAsnGetEffectiveEncodedLength((ASN_ELEMENT*)&pElement->Sub[cx]);
			}
		}
		// Primitif object
		else {
			pElement->ValueLength = pElement->ObjectLength;
		}
	}
	return pElement->ValueLength;
}

/// <summary>
/// Generate valid ASN.1 primitive element
/// </summary>
NTSTATUS KerbpAsnMakePrimitive(
	_Inout_ ASN_ELEMENT* pElement,
	_In_    CONST INT8   TagClass,
	_In_    CONST INT8   TagValue,
	_In_    CONST PBYTE  pBuffer,
	_In_    CONST INT32  Offset,
	_In_    CONST INT32  Length
) {
	if (pElement == NULL)
		return STATUS_UNSUCCESSFUL;
	if (TagClass < 0 || TagClass > 3)
		return STATUS_UNSUCCESSFUL;
	if (TagValue < 0)
		return STATUS_UNSUCCESSFUL;

	RtlZeroMemory(pElement, sizeof(ASN_ELEMENT));
	pElement->ObjectBuffer = pBuffer;
	pElement->ObjectLength = -1;
	pElement->ValueLength = Length;
	pElement->TagValue = TagValue;
	pElement->TagClass = TagClass;

	// Dummy call to update the internal lenght
	KerbpAsnGetEffectiveEncodedLength(pElement);
	KerbpAsnGetEffectiveValueLenght(pElement);
	return STATUS_SUCCESS;
}

/// <summary>
/// Generate valid ASN.1 constructed element
/// </summary>
NTSTATUS KerbpAsnMakeConstructed(
	_Inout_ ASN_ELEMENT*       pElement,
	_In_    CONST INT8         TagClass,
	_In_    CONST INT8         TagValue,
	_In_    CONST ASN_ELEMENT* pSubElements,
	_In_    CONST DWORD        NumberOfSubElements
) {
	if (pElement == NULL)
		return STATUS_UNSUCCESSFUL;
	if (TagClass < 0 || TagClass > 3)
		return STATUS_UNSUCCESSFUL;
	if (TagValue < 0)
		return STATUS_UNSUCCESSFUL;

	RtlZeroMemory(pElement, sizeof(ASN_ELEMENT));
	pElement->ObjectLength = -1;
	pElement->ValueLength = -1;
	pElement->TagValue = TagValue;
	pElement->TagClass = TagClass;

	// Allocate memory for the sub-elements
	if (NumberOfSubElements != 0x00) {
		pElement->SubElements = NumberOfSubElements;
		pElement->Sub = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(ASN_ELEMENT) * NumberOfSubElements);
		if (pElement->Sub == NULL)
			return STATUS_UNSUCCESSFUL;
		RtlCopyMemory(pElement->Sub, pSubElements, sizeof(ASN_ELEMENT) * NumberOfSubElements);
	}

	// Dummy call to update the internal lenght
	KerbpAsnGetEffectiveEncodedLength(pElement);
	KerbpAsnGetEffectiveValueLenght(pElement);
	return STATUS_SUCCESS;
}

/// <summary>
/// Change tag from an object
/// </summary>
NTSTATUS KerbpAsnMakeImplicit(
	_In_  ASN_ELEMENT* pElementIn,
	_In_  CONST INT8   TagClass,
	_In_  CONST INT8   TagValue,
	_Out_ ASN_ELEMENT* pElementOut
) {
	// Constructed
	if (pElementIn->SubElements != 0x00) {
		ASN_ELEMENT Out = { 0x00 };
		NTSTATUS Status = STATUS_SUCCESS;

		Status = KerbpAsnMakeConstructed(
			&Out,
			TagClass,
			TagValue,
			pElementIn->Sub,
			pElementIn->SubElements
		);
		if (NT_SUCCESS(Status))
			*pElementOut = Out;
		return Status;
	}

	// Primitif
	RtlZeroMemory(pElementOut, sizeof(ASN_ELEMENT));
	pElementOut->ObjectOffset = 0x00;
	pElementOut->ObjectLength = -1;
	pElementOut->TagClass = TagClass;
	pElementOut->TagValue = TagValue;

	pElementOut->ObjectBuffer = pElementIn->ObjectBuffer;
	pElementOut->ValueLength = pElementIn->ValueLength;
	pElementOut->ValueOffset = pElementIn->ValueOffset;

	KerbpAsnGetEffectiveEncodedLength(pElementOut);
	KerbpAsnGetEffectiveValueLenght(pElementOut);
	return STATUS_SUCCESS;
}

/// <summary>
/// Encode the value of an ASN.1 element
/// </summary>
INT32 KerbpAnsEncodeValue(
	_In_  ASN_ELEMENT* pElement,
	_In_  INT32        Start,
	_In_  INT32        End,
	_In_  INT32        RawElementOffset,
	_Out_ PBYTE        pRawElement
) {
	INT32 Origin = RawElementOffset;
	if (pElement->ObjectBuffer == NULL) {
		INT32 k = 0x00;
		for (DWORD cx = 0x00; cx < pElement->SubElements; cx++) {
			INT32 slen = KerbpAsnGetEffectiveEncodedLength((ASN_ELEMENT*)&pElement->Sub[cx]);
			RawElementOffset += KerbpAsnEncode(
				(ASN_ELEMENT*)&pElement->Sub[cx],
				Start - k,
				End - k,
				RawElementOffset,
				pRawElement
			);
			k += slen;
		}
	}
	else {
		INT32 from = max(0x00, Start);
		INT32 to = min(pElement->ValueLength, End);
		INT32 Lenght = to - from;
		if (Lenght > 0x00) {
			PBYTE src = pElement->ObjectBuffer + from + pElement->ValueOffset;
			PBYTE dst = pRawElement + RawElementOffset;
			RtlCopyMemory(dst, src, Lenght);
			RawElementOffset += Lenght;
		}
	}
	return RawElementOffset - Origin;
}

/// <summary>
/// Encode an ASN.1 element. Recursive.
/// </summary>
INT32 KerbpAsnEncode(
	_In_  ASN_ELEMENT* pElement,
	_In_  INT32        Start,
	_In_  INT32        End,
	_In_  DWORD        RawElementOffset,
	_Out_ PBYTE        pRawElement
) {
	// Local offset
	int offset = 0x00;

	// Encode the tag
	INT32 fb = pElement->TagClass << 6;
	fb += (pElement->SubElements != 0x00) ? 0x20 : 0x00;
	if (pElement->TagValue < 0x1F) {
		fb |= pElement->TagValue & 0x1F;
		if (Start <= offset && offset < End)
			pRawElement[RawElementOffset++] = (UCHAR)fb;
		offset++;
	}
	else {
		fb |= 0x1F;
		if (Start <= offset && offset < End)
			pRawElement[RawElementOffset++] = (UCHAR)fb;
		offset++;

		INT32 k = 0x00;
		for (INT32 v = pElement->TagValue; v > 0x00; v >>= 7, k += 7);
		while (k > 0x00) {
			k -= 7;
			INT32 v = (pElement->TagValue >> k) & 0x7F;
			if (k != 0x00)
				v |= 0x80;
			if (Start <= offset && offset < End)
				pRawElement[RawElementOffset++] = (UCHAR)v;
			offset++;
		}
	}

	// Encode length
	INT32 vlen = pElement->ValueLength;
	if (vlen < 0x80) {
		if (Start <= offset && offset < End)
			pRawElement[RawElementOffset++] = (UCHAR)vlen;
		offset++;
	}
	else {
		INT32 k = 0x00;
		for (INT32 v = vlen; v > 0; v >>= 8, k += 8);

		if (Start <= offset && offset < End)
			pRawElement[RawElementOffset++] = (UCHAR)(0x80 + (k >> 3));
		offset++;

		while (k > 0) {
			k -= 8;
			if (Start <= offset && offset < End)
				pRawElement[RawElementOffset++] = (UCHAR)(vlen >> 4);
			offset++;
		}
	}

	// Encode the data
	offset += KerbpAnsEncodeValue(
		pElement,
		Start - offset,
		End - offset,
		RawElementOffset,
		pRawElement
	);

	// Get the final size to return.
	return max(0x00, min(offset, End) - max(0x00, Start));
}

/// <summary>
/// Load the cryptdll module and get the KERBEROS_ECRYPT structure out of 
/// memory.
/// </summary>
NTSTATUS KerbpEncryptInternal(
	_In_  INT32            EType,
	_Out_ KERBEROS_ECRYPT* pECrypt
) {
	// Get base address of the module
	HMODULE hCryptDLL = LoadLibraryA("cryptdll.dll");
	if (hCryptDLL == NULL)
		return STATUS_UNSUCCESSFUL;

	// Get address of the function
	fnCDLocateCSystem CDLocateCSystem = GetProcAddress(hCryptDLL, "CDLocateCSystem");
	if (CDLocateCSystem == NULL)
		return STATUS_UNSUCCESSFUL;

	// Get the structure
	LPDWORD AddressOfStructure = NULL;
	INT32 Result = CDLocateCSystem(EType, &AddressOfStructure);
	RtlCopyMemory(pECrypt, AddressOfStructure, sizeof(KERBEROS_ECRYPT));
	return STATUS_SUCCESS;
}

/// <summary>
/// Encrypt data 
/// </summary>
NTSTATUS KerbpEncrypt(
	_In_  UINT8  EType,
	_In_  INT32  EncReason,
	_In_  PBYTE  Key,
	_In_  DWORD  KeyLength,
	_In_  PBYTE  BufferIn,
	_In_  DWORD  BufferInSize,
	_Out_ PBYTE* BufferOut,
	_Out_ DWORD* BufferOutSize
) {
	// Load the module to get the address of the structure containing
	// encryption functions
	NTSTATUS Status = STATUS_SUCCESS;
	KERBEROS_ECRYPT ECrypt = { 0x00 };
	Status = KerbpEncryptInternal(EType, &ECrypt);
	if (!NT_SUCCESS(Status) || ECrypt.Initialize == NULL)
		return Status;

	// Initialise
	LPVOID Context = NULL;
	INT32 Result = ((fnInitialize)ECrypt.Initialize)(
		Key,
		KeyLength,
		EncReason,
		&Context
	);
	if (Result != 0x00 || Context == NULL)
		return STATUS_UNSUCCESSFUL;

	// Get the output size 
	*BufferOutSize = BufferInSize;
	while ((*BufferOutSize % ECrypt.BlockSize) != 0x00)
		*BufferOutSize++;
	*BufferOutSize += ECrypt.Size;

	// Allocate memory 
	*BufferOut = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, *BufferOutSize);
	if (*BufferOut == NULL) {
		((fnFinish)ECrypt.Finish)(Context);
		return STATUS_UNSUCCESSFUL;
	}

	// Encrypt the data
	Result = ((fnEncrypt)ECrypt.Encrypt)(
		Context,
		BufferIn,
		BufferInSize,
		*BufferOut,
		BufferOutSize
	);

	return STATUS_SUCCESS;
}

NTSTATUS KerbGenerateSystemTimestampPAData(
	_In_  LPCSTR StringKey,
	_In_  DWORD  StringKeySize,
	_Out_ PBYTE* EncryptedTimestamp,
	_Out_ DWORD* EncryptedTimestampSize
) {
	// Get the system time
	SYSTEMTIME SystemTime = { 0x00 };
	GetSystemTime(&SystemTime);

	// Convert system time in a formated string
	CHAR* szSystemTime = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(SYSTEMTIME) + 2);
	if (szSystemTime == NULL)
		return STATUS_UNSUCCESSFUL;

	// Format the system time stamp
	NTSTATUS Status = STATUS_SUCCESS;
	Status = KerbpFormatTimestamp(
		&szSystemTime,
		sizeof(SYSTEMTIME) + 2,
		"%ld%02ld%02ld%02ld%02ld%02ldZ",
		SystemTime.wYear,
		SystemTime.wMonth,
		SystemTime.wDay,
		SystemTime.wHour,
		SystemTime.wMinute,
		SystemTime.wSecond
	);

	// Make a primitive element for the timestamp
	ASN_ELEMENT TimeStamp = { 0x00 };
	Status = KerbpAsnMakePrimitive(
		&TimeStamp,
		ASN_TAG_CLASS_UNIVERSAL,
		ASN_TAG_GENERALIZED_TIME,
		szSystemTime,
		0x00,
		0x0F
	);
	HeapFree(GetProcessHeap(), 0x00, szSystemTime);

	// Make a constructed element with a list of sub-elements
	ASN_ELEMENT Sequence1 = { 0x00 };
	ASN_ELEMENT Sequence2 = { 0x00 };
	Status = KerbpAsnMakeConstructed(
		&Sequence1,
		ASN_TAG_CLASS_UNIVERSAL,
		ASN_TAG_SEQUENCE,
		&TimeStamp,
		1
	);
	Status = KerbpAsnMakeImplicit(
		&Sequence1,
		ASN_TAG_CLASS_CONTEXT_SPECIFIC,
		0x00,
		&Sequence2
	);

	// Create the final constructed element with the previous data
	ASN_ELEMENT Final = { 0x00 };
	Status = KerbpAsnMakeConstructed(
		&Final,
		ASN_TAG_CLASS_UNIVERSAL,
		ASN_TAG_SEQUENCE,
		&Sequence2,
		1
	);

	// Encode the object
	PBYTE RawObject = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 0x7fffffff);
	INT32 RawObjectSize = KerbpAsnEncode(
		&Final,
		0x00,
		0x7fffffff,
		0x00,
		RawObject
	);
	if (Final.Sub)
		HeapFree(GetProcessHeap(), 0x00, Final.Sub);

	// Use the NTLM hash provided to encrypt the timestamp
	PBYTE Ptr = NULL;
	Status = KerbpEncrypt(
		KERBEROS_ETYPE_RC4_HMAC,
		KERBEROS_KEY_USAGE_AS_REQ_PA_ENC_TIMESTAMP,
		StringKey,
		StringKeySize,
		RawObject,
		RawObjectSize,
		&Ptr,
		EncryptedTimestampSize
	);
	if (!NT_SUCCESS(Status)) {
		// cnealup
	}

	// Cleanup and exit
	*EncryptedTimestamp = Ptr;
	return STATUS_SUCCESS;
}