#pragma once
#define NT_SUCCESS(Status)				(((NTSTATUS)(Status)) >= 0)
#define STATUS_UNSUCCESSFUL				0xC0000001
#define STATUS_INVALID_BUFFER_SIZE		0xC0000206