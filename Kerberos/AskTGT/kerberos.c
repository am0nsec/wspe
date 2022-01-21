
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
/// Get code point.
/// </summary>
INT32 KerbpGetCodePoint(
	_In_    PBYTE  String,
	_In_    INT32  StringSize,
	_Inout_ INT32* Offset
) {
	INT32 c = String[(*Offset)++];
	if (c >= 0xD800 && c < 0xDC00 && *Offset < StringSize) {
		INT32 d = String[*Offset];
		if (d >= 0xDC00 && d < 0xE000) {
			c = ((c & 0x3FF) << 10) + (d & 0x3FF) + 0x10000;
			(*Offset)++;
		}
	}
	return c;
}

/// <summary>
/// UTF8 encoding of a string.
/// </summary>
NTSTATUS KerbpEncodeUTF8(
	_In_  PBYTE  StringIn,
	_In_  INT32  StringInSize,
	_Out_ PBYTE* StringOut,
	_Out_ INT32* StringOutSize
) {
	// Allocate memory
	*StringOut = calloc(0x1, (StringInSize * 4) + sizeof(WCHAR));
	PBYTE dst = *StringOut;

	while (*StringOutSize < StringInSize) {
		INT32 cp = KerbpGetCodePoint(StringIn, StringInSize, StringOutSize);
		if (cp < 0x80) {
			*dst++ = (UCHAR)cp;
		}
		else if (cp < 0x800) {
			*dst++ = (UCHAR)(0xC0 + (cp >> 6));
			*dst++ = (UCHAR)(0x80 + (cp & 63));
		}
		else if (cp < 0x10000) {
			*dst++ = (UCHAR)(0xE0 + (cp >> 12));
			*dst++ = (UCHAR)(0x80 + ((cp >> 6) & 63));
			*dst++ = (UCHAR)(0x80 + (cp & 63));
		}
		else {
			*dst++ = (UCHAR)(0xF0 + (cp >> 18));
			*dst++ = (UCHAR)(0x80 + ((cp >> 12) & 63));
			*dst++ = (UCHAR)(0x80 + ((cp >> 6) & 63));
			*dst++ = (UCHAR)(0x80 + (cp & 63));
		}
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
			INT32 len = 0x00;
			for (DWORD cx = 0x00; cx < pElement->SubElements; cx++) {
				len += KerbpAsnGetEffectiveEncodedLength(&(((ASN_ELEMENT*)pElement->Sub)[cx]));
			}
			pElement->ValueLength = len;
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
		pElement->Sub = calloc(0x01, sizeof(ASN_ELEMENT) * NumberOfSubElements);
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
			(ASN_ELEMENT*)pElementIn->Sub,
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
/// Generate valid ASN.1 integer element.
/// </summary>
NTSTATUS KerbpAsnMakeInteger(
	_Inout_ ASN_ELEMENT* pElement,
	_In_    LONG         Value
) {
	INT32 k = 1;
	for (ULONG w = (ULONG)Value; w >= 0x80; w >>= 8, k++);

	// Allocate memory
	LPBYTE v = calloc(1, k);
	INT32 Length = k;
	for (ULONG w = (ULONG)Value; k > 0x00; w >>= 8) {
		v[--k] = (UCHAR)w;
	}

	return KerbpAsnMakePrimitive(
		pElement,
		ASN_TAG_CLASS_UNIVERSAL,
		ASN_TAG_INTEGER,
		v,
		0x00,
		Length
	);
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
			INT32 slen = KerbpAsnGetEffectiveEncodedLength(&(((ASN_ELEMENT*)pElement->Sub)[cx]));
			RawElementOffset += KerbpAsnEncode(
				&(((ASN_ELEMENT*)pElement->Sub)[cx]),
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
	fnCDLocateCSystem CDLocateCSystem = (fnCDLocateCSystem)GetProcAddress(hCryptDLL, "CDLocateCSystem");
	if (CDLocateCSystem == NULL)
		return STATUS_UNSUCCESSFUL;

	// Get the structure
	LPVOID AddressOfStructure = NULL;
	INT32 Result = CDLocateCSystem(EType, &AddressOfStructure);
	if (AddressOfStructure == NULL)
		return STATUS_UNSUCCESSFUL;

	// Get the structure.
	RtlCopyMemory(pECrypt, AddressOfStructure, sizeof(KERBEROS_ECRYPT));
	return STATUS_SUCCESS;
}

/// <summary>
/// Encrypt data 
/// </summary>
NTSTATUS KerbpEncrypt(
	_In_  INT32  EType,
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
	*BufferOut = calloc(0x01, *BufferOutSize);
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

/// <summary>
/// Generate ASN.1 element for system timestamp.
/// </summary>
NTSTATUS KerbpGenerateTimestamp(
	_Out_ ASN_ELEMENT* Timestamp
) {
	// Get the system time
	SYSTEMTIME SystemTime = { 0x00 };
	GetSystemTime(&SystemTime);

	// Convert system time in a formated string
	CHAR* szSystemTime = calloc(0x01, sizeof(SYSTEMTIME) + 2);
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
	ASN_ELEMENT Temp1 = { 0x00 };
	Status = KerbpAsnMakePrimitive(
		&Temp1,
		ASN_TAG_CLASS_UNIVERSAL,
		ASN_TAG_GENERALIZED_TIME,
		szSystemTime,
		0x00,
		0x0F
	);
	free(szSystemTime);

	// Make a constructed element with a list of sub-elements
	ASN_ELEMENT Temp2 = { 0x00 };
	ASN_ELEMENT Temp3 = { 0x00 };
	Status = KerbpAsnMakeConstructed(
		&Temp2,
		ASN_TAG_CLASS_UNIVERSAL,
		ASN_TAG_SEQUENCE,
		&Temp1,
		1
	);
	Status = KerbpAsnMakeImplicit(
		&Temp2,
		ASN_TAG_CLASS_CONTEXT_SPECIFIC,
		0x00,
		&Temp3
	);

	// Create the final constructed element with the previous data
	Status = KerbpAsnMakeConstructed(
		Timestamp,
		ASN_TAG_CLASS_UNIVERSAL,
		ASN_TAG_SEQUENCE,
		&Temp3,
		1
	);

	return STATUS_SUCCESS;
}

/// <summary>
/// Encrypt the timestamp with user NTLM hash.
/// </summary>
NTSTATUS KerbpEncryptTimestamp(
	_In_  LPBYTE          Key,
	_In_  DWORD           KeySize,
	_In_  ASN_ELEMENT*    Timestamp,
	_Out_ ENCRYPTED_DATA* EncryptedData,
	_Out_ DWORD*          EncryptedDataSize
) {
	NTSTATUS Status = STATUS_SUCCESS;

	// Encode the timestamp
	PBYTE RawTimestamp = calloc(0x01, Timestamp->ObjectLength + 0x10);
	INT32 RawTimestampSize = KerbpAsnEncode(
		Timestamp,
		0x00,
		Timestamp->ObjectLength + 0x10,
		0x00,
		RawTimestamp
	);
	if (Timestamp->Sub)
		free(Timestamp->Sub);

	// Encrypt the data
	Status = KerbpEncrypt(
		EncryptedData->EType,
		KERBEROS_KEY_USAGE_AS_REQ_PA_ENC_TIMESTAMP,
		Key,
		KeySize,
		RawTimestamp,
		RawTimestampSize,
		&EncryptedData->cipher,
		EncryptedDataSize
	);
	if (!NT_SUCCESS(Status)) {
		if (EncryptedData->cipher != NULL)
			free(EncryptedData->cipher);
		return STATUS_UNSUCCESSFUL;
	}

	// Cleanup and exit
	free(RawTimestamp);
	return Status;
}

/// <summary>
/// Encode ASN.1 encrypted-data element.
/// </summary>
NTSTATUS KerbpEncodeEncryptedData(
	_In_  ENCRYPTED_DATA* EncryptedData,
	_In_  DWORD           EncryptedDataSize,
	_Out_ PBYTE*          RawData,
	_Out_ DWORD*          RawDataSize
) {
	NTSTATUS Status = STATUS_SUCCESS;
	
	ASN_ELEMENT Temp1 = { 0x00 };
	ASN_ELEMENT Temp2 = { 0x00 };
	ASN_ELEMENT Temp3 = { 0x00 };

	// etype
	ASN_ELEMENT EType = { 0x00 };
	Status = KerbpAsnMakeInteger(&Temp1, EncryptedData->EType);
	Status = KerbpAsnMakeConstructed(
		&Temp2,
		ASN_TAG_CLASS_UNIVERSAL,
		ASN_TAG_SEQUENCE,
		&Temp1,
		0x01
	);
	Status = KerbpAsnMakeImplicit(
		&Temp2,
		ASN_TAG_CLASS_CONTEXT_SPECIFIC,
		0x00,
		&EType
	);

	// Reset
	RtlZeroMemory(&Temp1, sizeof(ASN_ELEMENT));
	RtlZeroMemory(&Temp2, sizeof(ASN_ELEMENT));

	// Encode all the data
	ASN_ELEMENT Cipher = { 0x00 };
	Status = KerbpAsnMakePrimitive(
		&Temp1,
		ASN_TAG_CLASS_UNIVERSAL,
		ASN_TAG_OCTET_STRING,
		EncryptedData->cipher,
		0x00,
		EncryptedDataSize
	);
	Status = KerbpAsnMakeConstructed(
		&Temp2,
		ASN_TAG_CLASS_UNIVERSAL,
		ASN_TAG_SEQUENCE,
		&Temp1,
		0x01
	);
	Status = KerbpAsnMakeImplicit(
		&Temp2,
		ASN_TAG_CLASS_CONTEXT_SPECIFIC,
		0x02,
		&Cipher
	);

	// Get sequence
	ASN_ELEMENT Elements[0x02] = { EType, Cipher };
	Status = KerbpAsnMakeConstructed(
		&Temp3,
		ASN_TAG_CLASS_UNIVERSAL,
		ASN_TAG_SEQUENCE,
		Elements,
		0x02
	);

	// Encode the sequence
	*RawData = calloc(0x01, Temp3.ObjectLength + 0x10);
	*RawDataSize = KerbpAsnEncode(
		&Temp3,
		0x00,
		Temp3.ObjectLength + 0x10,
		0x00,
		*RawData
	);
	if (Temp3.Sub)
		free(Temp3.Sub);
	return STATUS_SUCCESS;
}

/// <summary>
/// Generate kdc-options ASN.1 element.
/// </summary>
NTSTATUS KerbpGenerateKdcOptions(
	_In_  ULONG        Options,
	_Out_ ASN_ELEMENT* pElement
) {
	NTSTATUS Status = STATUS_SUCCESS;

	// Convert the options to little endian
	UCHAR Bytes[0x05] = { 0x00 };
	Bytes[0x01] = XLATE_UINT32(Options, 0x00);
	Bytes[0x02] = XLATE_UINT32(Options, 0x01);
	Bytes[0x03] = XLATE_UINT32(Options, 0x02);
	Bytes[0x04] = XLATE_UINT32(Options, 0x03);

	// Temporary elements
	ASN_ELEMENT Temp1 = { 0x00 };
	ASN_ELEMENT Temp2 = { 0x00 };

	// Get the sequence
	Status = KerbpAsnMakePrimitive(
		&Temp1,
		ASN_TAG_CLASS_UNIVERSAL,
		ASN_TAG_BIT_STRING,
		Bytes,
		0x00,
		0x05
	);
	Status = KerbpAsnMakeConstructed(
		&Temp2,
		ASN_TAG_CLASS_UNIVERSAL,
		ASN_TAG_SEQUENCE,
		&Temp1,
		0x01
	);
	Status = KerbpAsnMakeImplicit(
		&Temp2,
		ASN_TAG_CLASS_CONTEXT_SPECIFIC,
		0x00,
		pElement
	);

	return Status;
}

/// <summary>
/// Generate cname ASN.1 element.
/// </summary>
NTSTATUS KerbpGenerateCname(
	_In_  PCSTR        SecurityPrincipal,
	_In_  INT32        SecurityPrincipalSize,
	_Out_ ASN_ELEMENT* pElement
) {
	NTSTATUS Status = STATUS_SUCCESS;

	// Temporary elements
	ASN_ELEMENT Temp1 = { 0x00 };
	ASN_ELEMENT Temp2 = { 0x00 };
	
	// name-type
	ASN_ELEMENT NameType = { 0x0 };
	Status = KerbpAsnMakeInteger(&Temp1, KERBEROS_PRINCIPAL_TYPE_NT_PRINCIPAL);
	Status = KerbpAsnMakeConstructed(
		&Temp2,
		ASN_TAG_CLASS_UNIVERSAL,
		ASN_TAG_SEQUENCE,
		&Temp1,
		0x01
	);
	Status = KerbpAsnMakeImplicit(
		&Temp2,
		ASN_TAG_CLASS_CONTEXT_SPECIFIC,
		0x00,
		&NameType
	);

	// Reset
	RtlZeroMemory(&Temp1, sizeof(ASN_ELEMENT));
	RtlZeroMemory(&Temp2, sizeof(ASN_ELEMENT));

	// name-string
	ASN_ELEMENT NameString = { 0x00 };

	PBYTE EncodeSecurityPrincipal = NULL;
	INT32 EncodeSecurityPrincipalSize = 0x00;
	Status = KerbpEncodeUTF8(
		SecurityPrincipal,
		SecurityPrincipalSize,
		&EncodeSecurityPrincipal,
		&EncodeSecurityPrincipalSize
	);
	Status = KerbpAsnMakePrimitive(
		&Temp1,
		ASN_TAG_CLASS_UNIVERSAL,
		ASN_TAG_UTF8STRING,
		EncodeSecurityPrincipal,
		0x00,
		EncodeSecurityPrincipalSize
	);
	Status = KerbpAsnMakeImplicit(
		&Temp1,
		ASN_TAG_CLASS_UNIVERSAL,
		ASN_TAG_GENERAL_STRING,
		&NameString
	);

	// Reset
	RtlZeroMemory(&Temp1, sizeof(ASN_ELEMENT));
	RtlZeroMemory(&Temp2, sizeof(ASN_ELEMENT));

	// name-string sequence
	Status = KerbpAsnMakeConstructed(
		&Temp1,
		ASN_TAG_CLASS_UNIVERSAL,
		ASN_TAG_SEQUENCE,
		&NameString,
		0x01
	);
	Status = KerbpAsnMakeConstructed(
		&Temp2,
		ASN_TAG_CLASS_UNIVERSAL,
		ASN_TAG_SEQUENCE,
		&Temp1,
		0x01
	);
	RtlZeroMemory(&NameString, sizeof(ASN_ELEMENT));
	Status = KerbpAsnMakeImplicit(
		&Temp2,
		ASN_TAG_CLASS_CONTEXT_SPECIFIC,
		0x01,
		&NameString
	);

	// Reset
	RtlZeroMemory(&Temp1, sizeof(ASN_ELEMENT));
	RtlZeroMemory(&Temp2, sizeof(ASN_ELEMENT));

	// Final Sequence
	ASN_ELEMENT Elements[0x02] = { NameType, NameString };
	Status = KerbpAsnMakeConstructed(
		&Temp1,
		ASN_TAG_CLASS_UNIVERSAL,
		ASN_TAG_SEQUENCE,
		Elements,
		0x02
	);
	Status = KerbpAsnMakeConstructed(
		&Temp2,
		ASN_TAG_CLASS_UNIVERSAL,
		ASN_TAG_SEQUENCE,
		&Temp1,
		0x01
	);

	return KerbpAsnMakeImplicit(
		&Temp2,
		ASN_TAG_CLASS_CONTEXT_SPECIFIC,
		0x01,
		pElement
	);
}


/// <summary>
/// Generate ASN.1 elements for pvno and msg-type
/// </summary>
NTSTATUS KerbGeneratePvnoAndType(
	_Out_ ASN_ELEMENT* Pvno,
	_Out_ ASN_ELEMENT* MessageType
) {
	NTSTATUS Status = STATUS_SUCCESS;

	// Generate the ASN.1 element for the 
	ASN_ELEMENT Temp1 = { 0x00 };
	Status = KerbpAsnMakeInteger(&Temp1, 5);

	ASN_ELEMENT Temp2 = { 0x00 };
	Status = KerbpAsnMakeConstructed(
		&Temp2,
		ASN_TAG_CLASS_UNIVERSAL,
		ASN_TAG_SEQUENCE,
		&Temp1,
		0x01
	);
	Status = KerbpAsnMakeImplicit(
		&Temp2,
		ASN_TAG_CLASS_CONTEXT_SPECIFIC,
		0x01,
		Pvno
	);

	// Generate the ASN.1 element for the
	ASN_ELEMENT Temp3 = { 0x00 };
	ASN_ELEMENT Temp4 = { 0x00 };
	Status = KerbpAsnMakeInteger(&Temp3, KERBEROS_MESSAGE_TYPE_AS_REQ);
	Status = KerbpAsnMakeConstructed(
		&Temp4,
		ASN_TAG_CLASS_UNIVERSAL,
		ASN_TAG_SEQUENCE,
		&Temp3,
		0x01
	);
	Status = KerbpAsnMakeImplicit(
		&Temp4,
		ASN_TAG_CLASS_CONTEXT_SPECIFIC,
		0x02,
		MessageType
	);

	return Status;
}

/// <summary>
/// Generate the EncryptedData ASN.1 element containing the encrypted timestamp.
/// </summary>
NTSTATUS KerbGenerateEncryptedData(
	_In_  LPCSTR       StringKey,
	_In_  DWORD        StringKeySize,
	_Out_ ASN_ELEMENT* pElement 
) {
	NTSTATUS Status = STATUS_SUCCESS;

	ASN_ELEMENT Temp1 = { 0x00 };
	ASN_ELEMENT Temp2 = { 0x00 };

	// padata-type
	ASN_ELEMENT PdataType = { 0x00 };
	Status = KerbpAsnMakeInteger(&Temp1, KERBEROS_PDATA_TYPE_ENC_TIMESTAMP);
	Status = KerbpAsnMakeConstructed(
		&Temp2,
		ASN_TAG_CLASS_UNIVERSAL,
		ASN_TAG_SEQUENCE,
		&Temp1,
		0x01
	);
	Status = KerbpAsnMakeImplicit(
		&Temp2,
		ASN_TAG_CLASS_CONTEXT_SPECIFIC,
		0x01,
		&PdataType
	);

	// Reset
	RtlZeroMemory(&Temp1, sizeof(ASN_ELEMENT));
	RtlZeroMemory(&Temp2, sizeof(ASN_ELEMENT));

	// Generate the timestamp
	ASN_ELEMENT Timestamp = { 0x00 };
	Status = KerbpGenerateTimestamp(&Timestamp);

	// Encrypt the timestamp
	DWORD EncryptedDataSize = 0x00;
	ENCRYPTED_DATA EncryptedData = { 0x00 };
	EncryptedData.EType = KERBEROS_ETYPE_RC4_HMAC;

	Status = KerbpEncryptTimestamp(
		StringKey,
		StringKeySize,
		&Timestamp,
		&EncryptedData,
		&EncryptedDataSize
	);

	// Get encoded data
	PBYTE RawEncryptedData = NULL;
	DWORD RawEncryptedDataSize = 0x00;
	KerbpEncodeEncryptedData(
		&EncryptedData,
		EncryptedDataSize,
		&RawEncryptedData,
		&RawEncryptedDataSize
	);

	// padata-value
	ASN_ELEMENT PdataValue = { 0x00 };
	Status = KerbpAsnMakePrimitive(
		&Temp1,
		ASN_TAG_CLASS_UNIVERSAL,
		ASN_TAG_OCTET_STRING,
		RawEncryptedData,
		0x00,
		RawEncryptedDataSize
	);
	Status = KerbpAsnMakeConstructed(
		&Temp2,
		ASN_TAG_CLASS_UNIVERSAL,
		ASN_TAG_SEQUENCE,
		&Temp1,
		0x01
	);
	Status = KerbpAsnMakeImplicit(
		&Temp2,
		ASN_TAG_CLASS_CONTEXT_SPECIFIC,
		0x02,
		&PdataValue
	);

	// Create sequence for both element.
	ASN_ELEMENT Elements[0x02] = { PdataType, PdataValue };
	return KerbpAsnMakeConstructed(
		pElement,
		ASN_TAG_CLASS_UNIVERSAL,
		ASN_TAG_SEQUENCE,
		Elements,
		0x02
	);
}

/// <summary>
/// Generate the PacRequest ASN.1 element. 
/// </summary>
NTSTATUS KerbGeneratePac(
	_Out_ ASN_ELEMENT* pElement
) {
	NTSTATUS Status = STATUS_SUCCESS;

	ASN_ELEMENT Temp1 = { 0x00 };
	ASN_ELEMENT Temp2 = { 0x00 };

	// padata-type
	ASN_ELEMENT PdataType = { 0x00 };
	Status = KerbpAsnMakeInteger(&Temp1, KERBEROS_PDATA_TYPE_PA_PAC_REQUEST);
	Status = KerbpAsnMakeConstructed(
		&Temp2,
		ASN_TAG_CLASS_UNIVERSAL,
		ASN_TAG_SEQUENCE,
		&Temp1,
		0x01
	);
	Status = KerbpAsnMakeImplicit(
		&Temp2,
		ASN_TAG_CLASS_CONTEXT_SPECIFIC,
		0x01,
		&PdataType
	);

	// Reset
	RtlZeroMemory(&Temp1, sizeof(ASN_ELEMENT));
	RtlZeroMemory(&Temp2, sizeof(ASN_ELEMENT));

	// Generate the PAC request.
	ASN_ELEMENT PdataValue = { 0x00 };
	PBYTE Blob[0x07] = { 0x30, 0x05, 0xa0, 0x03, 0x01, 0x01, 0x01 };
	Status = KerbpAsnMakePrimitive(
		&Temp1,
		ASN_TAG_CLASS_UNIVERSAL,
		ASN_TAG_OCTET_STRING,
		Blob,
		0x00,
		0x07
	);
	Status = KerbpAsnMakeConstructed(
		&Temp2,
		ASN_TAG_CLASS_UNIVERSAL,
		ASN_TAG_SEQUENCE,
		&Temp1,
		0x01
	);
	Status = KerbpAsnMakeImplicit(
		&Temp2,
		ASN_TAG_CLASS_CONTEXT_SPECIFIC,
		0x02,
		&PdataValue
	);

	// Create sequence for both element.
	ASN_ELEMENT Elements[0x02] = { PdataType, PdataValue };
	return KerbpAsnMakeConstructed(
		pElement,
		ASN_TAG_CLASS_UNIVERSAL,
		ASN_TAG_SEQUENCE,
		Elements,
		0x02
	);
}

/// <summary>
/// Generate the KDC-REQ-BODY ASN.1 element.
/// </summary>
NTSTATUS KerbGenerateKDCReqBody(
	_In_  PBYTE        DomainName,
	_In_  PBYTE        SecurityPrincipal,
	_Out_ ASN_ELEMENT* pElement
) {
	NTSTATUS Status = STATUS_SUCCESS;

	// kdc-options
	ASN_ELEMENT KdcOptions = { 0x00 };
	Status = KerbpGenerateKdcOptions(
		(KERBEROS_KDC_OPTION_FORWARDABLE | KERBEROS_KDC_OPTION_RENEWABLE | KERBEROS_KDC_OPTION_RENEWABLEOK),
		&KdcOptions
	);

	// cname
	ASN_ELEMENT Cname = { 0x00 };
	Status = KerbpGenerateCname(
		SecurityPrincipal,
		strlen(SecurityPrincipal),
		&Cname
	);

}