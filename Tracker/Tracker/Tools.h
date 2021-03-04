#ifndef _TOOLS_H_
#define _TOOLS_H_

typedef struct _THREAD_BASIC_INFORMATION {
	NTSTATUS ExitStatus;
	PTEB TebBaseAddress;
	CLIENT_ID ClientId;
	ULONG_PTR AffinityMask;
	KPRIORITY Priority;
	ULONG BasePriority;
} THREAD_BASIC_INFORMATION;

ULONG64
WINAPI
GetThreadTeb(
	IN HANDLE ThreadHandle
);

ULONG64
WINAPI
GetThreadProcessHeap(
	IN HANDLE ProcessHandle,
	IN HANDLE ThreadHandle
);

VOID
WINAPI
InitProcessBlock(
	IN HANDLE ProcessHandle,
	IN HANDLE ThreadHandle
);

#endif
