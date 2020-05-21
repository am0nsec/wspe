#pragma once
#include <Windows.h>

/*--------------------------------------------------------------------
  Macros.
--------------------------------------------------------------------*/
#ifndef NT_SUCCESS
#define NT_SUCCESS(StatCode)  ((NTSTATUS)(StatCode) >= 0)
#endif
#ifndef DEVICE_NOTIFY_CALLBACK
#define DEVICE_NOTIFY_CALLBACK 2
#endif

#define OBJ_CASE_INSENSITIVE    0x00000040L

#define STATUS_SUCCESS          0x00000000
#define STATUS_NO_MORE_ENTRIES  0x8000001AL
#define STATUS_UNSUCCESSFUL     0xC0000001
#define STATUS_BUFFER_TOO_SMALL 0xC0000023

#define InitializeObjectAttributes( p, n, a, r, s ) { \
	(p)->Length = sizeof( OBJECT_ATTRIBUTES );          \
	(p)->RootDirectory = r;                             \
	(p)->Attributes = a;                                \
	(p)->ObjectName = n;                                \
	(p)->SecurityDescriptor = s;                        \
	(p)->SecurityQualityOfService = NULL;               \
}

/*--------------------------------------------------------------------
  Windows structures.
--------------------------------------------------------------------*/
typedef struct _LSA_UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} LSA_UNICODE_STRING, * PLSA_UNICODE_STRING, UNICODE_STRING, * PUNICODE_STRING, * PUNICODE_STR;

typedef struct _OBJECT_ATTRIBUTES {
    ULONG           Length;
    PVOID           RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG           Attributes;
    PVOID           SecurityDescriptor;
    PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

typedef struct _OBJECT_DIRECTORY_INFORMATION {
    UNICODE_STRING Name;
    UNICODE_STRING TypeName;
} OBJECT_DIRECTORY_INFORMATION, * POBJECT_DIRECTORY_INFORMATION;

enum DirectoryAccess {
    DIRECTORY_QUERY = 0x0001,
    DIRECTORY_TRAVERSE = 0x0002,
    DIRECTORY_CREATE_OBJECT = 0x0004,
    DIRECTORY_CREATE_SUBDIRECTORY = 0x0008,
    DIRECTORY_ALL_ACCESS = STANDARD_RIGHTS_ALL | 0xF
};

