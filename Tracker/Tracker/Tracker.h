#include <unicorn/unicorn.h>
#include <capstone/capstone.h>
#include <winternl.h>
#include <psapi.h>
#include "Tools.h"
#include "Gdt.h"
#include "Except.h"
#include "Stack.h"

#pragma warning(disable:4047)
#pragma warning(disable:4022)
#pragma warning(disable:4024)

typedef struct _CORE_BLOCK {
	uc_engine* uc_handle;
	uc_err uc_error;
	uc_hook uc_hook_code;
	uc_hook uc_hook_insn_syscall;
	uc_hook uc_hook_intr;

	csh cs_handle;
	cs_err cs_error;
}CORE_BLOCK, * PCORE_BLOCK;

typedef struct _PROCESS_BLOCK {
	HANDLE ProcessHandle;
	HANDLE ThreadHandle;

	NT_TIB TIB;
	ULONG64 ThreadTeb;
	ULONG64 ProcessPeb;
	ULONG64 ProcessHeap;
	ULONG64 ImageBase;
	ULONG SizeOfImage;
	ULONG64 EntryPoint;
	UCHAR EntryPointCode[2];

	ULONG64 ExecuteFromRip;
	ULONG64 ExecuteEnd;

	EXCEPTION_RECORD ExceptionRecord;
	CONTEXT ContextRecord;
}PROCESS_BLOCK, * PPROCESS_BLOCK;

extern CORE_BLOCK CoreBlock;
extern PROCESS_BLOCK ProcessBlock;