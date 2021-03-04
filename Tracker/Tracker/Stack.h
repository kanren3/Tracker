#ifndef _STACK_H_
#define _STACK_H_

#ifdef __cplusplus
/* Assume byte packing throughout */
extern "C" {
#endif	/* __cplusplus */

	typedef struct _CALLERS {
		PVOID* EstablisherFrame;
		PVOID Establisher;
	}CALLERS, * PCALLERS;

	DECLSPEC_NOINLINE
		ULONG
		NTAPI
		WalkFrameChain(
			__out PCALLERS Callers,
			__in ULONG Count
		);

	NTSYSAPI
		PVOID
		NTAPI
		RtlImageDirectoryEntryToData(
			PVOID BaseOfImage,
			BOOLEAN MappedAsImage,
			USHORT DirectoryEntry,
			PULONG Size
		);

	typedef struct _SYMBOL {
		LDR_DATA_TABLE_ENTRY64 DataTableEntry;
		PVOID Address;
		PCHAR String;
		USHORT Ordinal;
		LONG Offset;
	}SYMBOL, * PSYMBOL;

	VOID
		NTAPI
		PrintSymbol(
			__in PCSTR Prefix,
			__in PSYMBOL Symbol
		);

	VOID
		NTAPI
		WalkImageSymbol(
			__in PVOID Address,
			__inout PSYMBOL Symbol
		);

	VOID
		NTAPI
		FindSymbol(
			__in PVOID Address,
			__inout PSYMBOL Symbol
		);

	VOID
		NTAPI
		FindAndPrintSymbol(
			__in PCSTR Prefix,
			__in PVOID Address
		);

	VOID
		NTAPI
		PrintFrameChain(
			__in PCSTR Prefix,
			__in PCALLERS Callers,
			__in_opt ULONG FramesToSkip,
			__in ULONG Count
		);

#ifdef __cplusplus
}
#endif	/* __cplusplus */

#endif // !_STACK_H_