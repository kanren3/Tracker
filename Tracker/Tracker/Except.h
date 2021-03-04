#ifndef _EXCEPT_H_
#define _EXCEPT_H_

#define UNWIND_HISTORY_TABLE_NONE 0
#define UNWIND_HISTORY_TABLE_LOCAL 2

#define UNWIND_HISTORY_TABLE_NONE 0
#define UNWIND_HISTORY_TABLE_GLOBAL 1
#define UNWIND_HISTORY_TABLE_LOCAL 2

#define STATUS_UNWIND                    ((NTSTATUS)0xC0000027L)
#define STATUS_BAD_STACK                 ((NTSTATUS)0xC0000028L)
#define STATUS_BAD_FUNCTION_TABLE        ((NTSTATUS)0xC00000FFL)

#define ARGUMENT_PRESENT(ArgumentPointer)    (\
    (CHAR *)((ULONG_PTR)(ArgumentPointer)) != (CHAR *)(NULL) )

#define LDR_VIEW_TO_DATAFILE(x) ((PVOID)(((ULONG_PTR)(x)) |  (ULONG_PTR)1))
#define LDR_IS_DATAFILE(x)              (((ULONG_PTR)(x)) &  (ULONG_PTR)1)
#define LDR_IS_VIEW(x)                  (!LDR_IS_DATAFILE(x))
#define LDR_DATAFILE_TO_VIEW(x) ((PVOID)(((ULONG_PTR)(x)) & ~(ULONG_PTR)1))

#define SIZE64_PREFIX 0x48
#define ADD_IMM8_OP 0x83
#define ADD_IMM32_OP 0x81
#define JMP_IMM8_OP 0xeb
#define JMP_IMM32_OP 0xe9
#define JMP_IND_OP 0xff
#define LEA_OP 0x8d
#define REP_PREFIX 0xf3
#define POP_OP 0x58
#define RET_OP 0xc3
#define RET_OP_2 0xc2

#define IS_REX_PREFIX(x) (((x) & 0xf0) == 0x40)

typedef ULONG LOGICAL;

typedef enum _FUNCTION_TABLE_TYPE {
	RF_SORTED,
	RF_UNSORTED,
	RF_CALLBACK
} FUNCTION_TABLE_TYPE;

typedef struct _DYNAMIC_FUNCTION_TABLE {
	LIST_ENTRY ListEntry;
	PRUNTIME_FUNCTION FunctionTable;
	LARGE_INTEGER TimeStamp;
	ULONG64 MinimumAddress;
	ULONG64 MaximumAddress;
	ULONG64 BaseAddress;
	PGET_RUNTIME_FUNCTION_CALLBACK Callback;
	PVOID Context;
	PWSTR OutOfProcessCallbackDll;
	FUNCTION_TABLE_TYPE Type;
	ULONG EntryCount;
} DYNAMIC_FUNCTION_TABLE, * PDYNAMIC_FUNCTION_TABLE;

typedef struct _PEB_LDR_DATA64 {
	ULONG Length;
	BOOLEAN Initialized;
	HANDLE SsHandle;
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
	PVOID EntryInProgress;
} PEB_LDR_DATA64, * PPEB_LDR_DATA64;

typedef struct _LDR_DATA_TABLE_ENTRY64 {
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	USHORT LoadCount;
	USHORT TlsIndex;
	union {
		LIST_ENTRY HashLinks;
		struct {
			PVOID SectionPointer;
			ULONG CheckSum;
		};
	};
	union {
		struct {
			ULONG TimeDateStamp;
		};
		struct {
			PVOID LoadedImports;
		};
	};
	PVOID EntryPointActivationContext;

	PVOID PatchInformation;

} LDR_DATA_TABLE_ENTRY64, * PLDR_DATA_TABLE_ENTRY64;

typedef union _UNWIND_CODE {
	struct {
		UCHAR CodeOffset;
		UCHAR UnwindOp : 4;
		UCHAR OpInfo : 4;
	};

	USHORT FrameOffset;
} UNWIND_CODE, * PUNWIND_CODE;

typedef struct _UNWIND_INFO {
	UCHAR Version : 3;
	UCHAR Flags : 5;
	UCHAR SizeOfProlog;
	UCHAR CountOfCodes;
	UCHAR FrameRegister : 4;
	UCHAR FrameOffset : 4;
	UNWIND_CODE UnwindCode[1];

	//
	// The unwind codes are followed by an optional DWORD aligned field that
	// contains the exception handler address or a function table entry if
	// chained unwind information is specified. If an exception handler address
	// is specified, then it is followed by the language specified exception
	// handler data.
	//
	//  union {
	//      struct {
	//          ULONG ExceptionHandler;
	//          ULONG ExceptionData[];
	//      };
	//
	//      RUNTIME_FUNCTION FunctionEntry;
	//  };
	//

} UNWIND_INFO, * PUNWIND_INFO;

typedef struct DECLSPEC_ALIGN(16) _M128 {
	ULONGLONG Low;
	LONGLONG High;
} M128, * PM128;

typedef enum _UNWIND_OP_CODES {
	UWOP_PUSH_NONVOL = 0,
	UWOP_ALLOC_LARGE,
	UWOP_ALLOC_SMALL,
	UWOP_SET_FPREG,
	UWOP_SAVE_NONVOL,
	UWOP_SAVE_NONVOL_FAR,
	UWOP_SAVE_XMM,
	UWOP_SAVE_XMM_FAR,
	UWOP_SAVE_XMM128,
	UWOP_SAVE_XMM128_FAR,
	UWOP_PUSH_MACHFRAME
} UNWIND_OP_CODES, * PUNWIND_OP_CODES;

PVOID
UcRtlImageDirectoryEntryToData(
	IN PVOID Base,
	IN BOOLEAN MappedAsImage,
	IN USHORT DirectoryEntry,
	OUT PULONG Size
);

BOOLEAN
UcRtlDispatchException(
	IN PEXCEPTION_RECORD ExceptionRecord,
	IN PCONTEXT ContextRecord
);

#endif