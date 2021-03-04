#include "Tracker.h"

NTSTATUS
FindEntryForKernelImageAddress(
	__in PVOID Address,
	__out PLDR_DATA_TABLE_ENTRY64 DataTableEntry
)
{
	NTSTATUS Status = 0x8000001A;
	PVOID Base = NULL;
	ULONG_PTR Bound;

	PEB Peb;
	PEB_LDR_DATA64 Ldr;
	PLIST_ENTRY ModuleListHead;
	PLIST_ENTRY Next;
	LDR_DATA_TABLE_ENTRY64 Entry;

	PRUNTIME_FUNCTION FunctionTable = NULL;

	if (ProcessBlock.ProcessPeb != NULL) {
		uc_mem_read(
			CoreBlock.uc_handle,
			ProcessBlock.ProcessPeb,
			&Peb,
			sizeof(Peb));

		uc_mem_read(
			CoreBlock.uc_handle,
			Peb.Ldr,
			&Ldr,
			sizeof(Ldr));

		ModuleListHead = (PLIST_ENTRY)((PUCHAR)Peb.Ldr + 0x10);
		Next = Ldr.InLoadOrderModuleList.Flink;

		if (Next != NULL) {
			while (Next != ModuleListHead) {
				ReadProcessMemory(
					ProcessBlock.ProcessHandle,
					Next,
					&Entry,
					sizeof(Entry),
					NULL);
				ReadProcessMemory(
					ProcessBlock.ProcessHandle,
					Next,
					&Next,
					sizeof(Next),
					NULL);

				Base = Entry.DllBase;
				Bound = (ULONG_PTR)Base + Entry.SizeOfImage;

				if ((ULONG_PTR)Address >= (ULONG_PTR)Base &&
					(ULONG_PTR)Address < (ULONG_PTR)Bound) {
					*DataTableEntry = Entry;
					Status = 0;
					break;
				}
			}
		}
	}
	
	return Status;
}

VOID
NTAPI
PrintSymbol(
	__in PCSTR Prefix,
	__in PSYMBOL Symbol
)
{
	WCHAR DllName[256] = { 0 };
	CHAR String[64] = { 0 };

	uc_mem_read(CoreBlock.uc_handle,
		Symbol->DataTableEntry.BaseDllName.Buffer,
		DllName,
		Symbol->DataTableEntry.BaseDllName.Length);

	if (Symbol->String)
	{
		uc_mem_read(CoreBlock.uc_handle,
			Symbol->String,
			String,
			sizeof(String));
	}

	if (NULL != Symbol->String) {
		if (0 == Symbol->Offset) {
#ifndef PUBLIC
			printf(
				"%s < %p > %S!%hs\n",
				Prefix,
				Symbol->Address,
				DllName,
				Symbol->String);
#endif // !PUBLIC
		}
		else {
#ifndef PUBLIC
			printf(
				"%s < %p > %S!%hs + %x\n",
				Prefix,
				Symbol->Address,
				DllName,
				Symbol->String,
				Symbol->Offset);
#endif // !PUBLIC
		}
	}
	else if (0 != Symbol->Ordinal) {
		if (0 == Symbol->Offset) {
#ifndef PUBLIC
			printf(
				"%s < %p > %S!@%d\n",
				Prefix,
				Symbol->Address,
				DllName,
				Symbol->Ordinal);
#endif // !PUBLIC
		}
		else {
#ifndef PUBLIC
			printf(
				"%s < %p > %S!@%d + %x\n",
				Prefix,
				Symbol->Address,
				DllName,
				Symbol->Ordinal,
				Symbol->Offset);
#endif // !PUBLIC
		}
	}
	else if (NULL != Symbol->DataTableEntry.SizeOfImage) {
#ifndef PUBLIC
		printf(
			"%s < %p > %S + %x\n",
			Prefix,
			Symbol->Address,
			DllName,
			Symbol->Offset);
#endif // !PUBLIC
	}
	else {
#ifndef PUBLIC
		printf(
			"%s < %p > symbol not found\n",
			Prefix,
			Symbol->Address);
#endif // !PUBLIC
	}
}

VOID
NTAPI
WalkImageSymbol(
	__in PVOID Address,
	__inout PSYMBOL Symbol
)
{
	NTSTATUS Status = 0;
	PIMAGE_EXPORT_DIRECTORY ExportDirectoryPointer = NULL;
	IMAGE_EXPORT_DIRECTORY ExportDirectory;
	ULONG Size = 0;
	PULONG NameTablePointr = NULL;
	ULONG NameTable = NULL;
	PUSHORT OrdinalTablePointr = NULL;
	USHORT OrdinalTable = NULL;
	PULONG AddressTablePointr = NULL;
	ULONG AddressTable = NULL;
	PSTR NameTableName = NULL;
	USHORT HintIndex = 0;
	USHORT NameIndex = 0;
	PVOID ProcedureAddress = NULL;
	PVOID NearAddress = NULL;

	Symbol->Address = Address;

	Symbol->Offset =
		(ULONG_PTR)Address - (ULONG_PTR)Symbol->DataTableEntry.DllBase;

	ExportDirectoryPointer = UcRtlImageDirectoryEntryToData(
		Symbol->DataTableEntry.DllBase,
		TRUE,
		IMAGE_DIRECTORY_ENTRY_EXPORT,
		&Size);

	if (NULL != ExportDirectoryPointer) {

		uc_mem_read(CoreBlock.uc_handle, ExportDirectoryPointer, &ExportDirectory, sizeof(ExportDirectory));

		NameTablePointr =
			(PCHAR)Symbol->DataTableEntry.DllBase + ExportDirectory.AddressOfNames;

		OrdinalTablePointr =
			(PCHAR)Symbol->DataTableEntry.DllBase + ExportDirectory.AddressOfNameOrdinals;

		AddressTablePointr =
			(PCHAR)Symbol->DataTableEntry.DllBase + ExportDirectory.AddressOfFunctions;

		if (NULL != NameTablePointr &&
			NULL != OrdinalTablePointr &&
			NULL != AddressTablePointr) {
			for (HintIndex = 0;
				HintIndex < ExportDirectory.NumberOfFunctions;
				HintIndex++) {
				uc_mem_read(CoreBlock.uc_handle, AddressTablePointr + HintIndex, &AddressTable, sizeof(AddressTable));
				ProcedureAddress =
					(PCHAR)Symbol->DataTableEntry.DllBase + AddressTable;

				if ((ULONG_PTR)ProcedureAddress <= (ULONG_PTR)Symbol->Address &&
					(ULONG_PTR)ProcedureAddress > (ULONG_PTR)NearAddress) {
					NearAddress = ProcedureAddress;

					for (NameIndex = 0;
						NameIndex < ExportDirectory.NumberOfNames;
						NameIndex++) {
						uc_mem_read(CoreBlock.uc_handle, OrdinalTablePointr + NameIndex, &OrdinalTable, sizeof(OrdinalTable));
						if (HintIndex == OrdinalTable) {
							uc_mem_read(CoreBlock.uc_handle, NameTablePointr + HintIndex, &NameTable, sizeof(NameTable));
							Symbol->String =
								(PCHAR)Symbol->DataTableEntry.DllBase + NameTable;
						}
					}

					Symbol->Ordinal =
						HintIndex + ExportDirectory.Base;

					Symbol->Offset =
						(ULONG_PTR)Symbol->Address - (ULONG_PTR)ProcedureAddress;
				}
			}
		}
	}
}

VOID
NTAPI
FindSymbol(
	__in PVOID Address,
	__inout PSYMBOL Symbol
)
{
	if (NT_SUCCESS(FindEntryForKernelImageAddress(
		Address,
		&Symbol->DataTableEntry))) {
		WalkImageSymbol(Address, Symbol);
	}
}

VOID
NTAPI
FindAndPrintSymbol(
	__in PCSTR Prefix,
	__in PVOID Address
)
{
	SYMBOL Symbol = { 0 };

	FindSymbol(Address, &Symbol);
	PrintSymbol(Prefix, &Symbol);
}

VOID
NTAPI
PrintFrameChain(
	__in PCSTR Prefix,
	__in PCALLERS Callers,
	__in_opt ULONG FramesToSkip,
	__in ULONG Count
)
{
	ULONG Index = 0;

	for (Index = FramesToSkip;
		Index < Count;
		Index++) {
		FindAndPrintSymbol(
			Prefix,
			Callers[Index].Establisher);
	}
}
