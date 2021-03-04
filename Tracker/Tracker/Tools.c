#include "Tracker.h"

ULONG64
WINAPI
GetThreadTeb(
	IN HANDLE ThreadHandle
)
{
	THREAD_BASIC_INFORMATION ThreadInformation = { 0 };

	NtQueryInformationThread(
		ThreadHandle,
		0,
		&ThreadInformation,
		sizeof(ThreadInformation),
		NULL);

	return ThreadInformation.TebBaseAddress;
}

ULONG64
WINAPI
GetThreadProcessHeap(
	IN HANDLE ProcessHandle,
	IN HANDLE ThreadHandle
)
{
	THREAD_BASIC_INFORMATION ThreadInformation = { 0 };

	NtQueryInformationThread(
		ThreadHandle,
		0,
		&ThreadInformation,
		sizeof(ThreadInformation),
		NULL);

	ULONG64 ProcessPeb = 0;
	ULONG64 ProcessHeap = 0;

	ReadProcessMemory(
		ProcessHandle,
		(PUCHAR)ThreadInformation.TebBaseAddress + 0x60,
		&ProcessPeb,
		8,
		NULL);

	ReadProcessMemory(
		ProcessHandle,
		ProcessPeb + 0x30,
		&ProcessHeap,
		8,
		NULL);

	return ProcessHeap;
}

VOID
WINAPI
InitProcessBlock(
	IN HANDLE ProcessHandle,
	IN HANDLE ThreadHandle
)
{
	THREAD_BASIC_INFORMATION ThreadInformation = { 0 };
	ULONG64 ProcessPeb = 0;
	ULONG64 Ldr = 0;

	NtQueryInformationThread(
		ThreadHandle,
		0,
		&ThreadInformation,
		sizeof(ThreadInformation),
		NULL);

	ReadProcessMemory(
		ProcessHandle,
		(PUCHAR)ThreadInformation.TebBaseAddress + 0x60,
		&ProcessPeb,
		8,
		NULL);

	ProcessBlock.ProcessPeb = ProcessPeb;

	ReadProcessMemory(
		ProcessHandle,
		ProcessPeb + 0x30,
		&ProcessBlock.ProcessHeap,
		8,
		NULL);

	ReadProcessMemory(
		ProcessHandle,
		ProcessPeb + 0x18,
		&Ldr,
		8,
		NULL);

	ReadProcessMemory(
		ProcessHandle,
		(PUCHAR)ThreadInformation.TebBaseAddress,
		&ProcessBlock.TIB,
		sizeof(ProcessBlock.TIB),
		NULL);
}