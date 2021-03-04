#include "Tracker.h"

ULONG HistoryTotal = 0;
ULONG HistoryGlobal = 0;
ULONG HistoryGlobalHits = 0;
ULONG HistorySearch = 0;
ULONG HistorySearchHits = 0;
ULONG HistoryInsert = 0;
ULONG HistoryInsertHits = 0;

UCHAR RtlpUnwindOpSlotTable[] = {
	1,          // UWOP_PUSH_NONVOL
	2,          // UWOP_ALLOC_LARGE (or 3, special cased in lookup code)
	1,          // UWOP_ALLOC_SMALL
	1,          // UWOP_SET_FPREG
	2,          // UWOP_SAVE_NONVOL
	3,          // UWOP_SAVE_NONVOL_FAR
	2,          // UWOP_SAVE_XMM
	3,          // UWOP_SAVE_XMM_FAR
	2,          // UWOP_SAVE_XMM128
	3,          // UWOP_SAVE_XMM128_FAR
	1           // UWOP_PUSH_MACHFRAME
};

VOID
RtlRaiseStatus(
    IN NTSTATUS Status
);

VOID
UcRtlpGetStackLimits(
	OUT PULONG64 LowLimit,
	OUT PULONG64 HighLimit
)
{
	*LowLimit = ProcessBlock.TIB.StackLimit;
	*HighLimit = ProcessBlock.TIB.StackBase;
}

VOID
UcRtlpCopyContext(
    OUT PCONTEXT Destination,
    IN PCONTEXT Source
)
{
    Destination->Rip = Source->Rip;
    Destination->Rbx = Source->Rbx;
    Destination->Rsp = Source->Rsp;
    Destination->Rbp = Source->Rbp;
    Destination->Rsi = Source->Rsi;
    Destination->Rdi = Source->Rdi;
    Destination->R12 = Source->R12;
    Destination->R13 = Source->R13;
    Destination->R14 = Source->R14;
    Destination->R15 = Source->R15;
    Destination->Xmm6 = Source->Xmm6;
    Destination->Xmm7 = Source->Xmm7;
    Destination->Xmm8 = Source->Xmm8;
    Destination->Xmm9 = Source->Xmm9;
    Destination->Xmm10 = Source->Xmm10;
    Destination->Xmm11 = Source->Xmm11;
    Destination->Xmm12 = Source->Xmm12;
    Destination->Xmm13 = Source->Xmm13;
    Destination->Xmm14 = Source->Xmm14;
    Destination->Xmm15 = Source->Xmm15;
    Destination->SegCs = Source->SegCs;
    Destination->SegSs = Source->SegSs;
    Destination->MxCsr = Source->MxCsr;
    Destination->EFlags = Source->EFlags;
}

PIMAGE_SECTION_HEADER
UcRtlSectionTableFromVirtualAddress(
    IN IMAGE_NT_HEADERS NtHeaders,
    IN PVOID Base,
    IN ULONG Address
)
{
    ULONG i;
	IMAGE_DOS_HEADER DosHeader;
    PIMAGE_NT_HEADERS NtHeadersPointer;
    PIMAGE_SECTION_HEADER NtSectionPointer;
    IMAGE_SECTION_HEADER NtSection;

	uc_mem_read(CoreBlock.uc_handle, Base, &DosHeader, sizeof(DosHeader));
    NtHeadersPointer = (PIMAGE_NT_HEADERS)((ULONG64)Base + DosHeader.e_lfanew);

    NtSectionPointer = (PIMAGE_SECTION_HEADER)((ULONG64)NtHeadersPointer +
        FIELD_OFFSET(IMAGE_NT_HEADERS, OptionalHeader) +
        NtHeaders.FileHeader.SizeOfOptionalHeader);

    uc_mem_read(CoreBlock.uc_handle, NtSectionPointer, &NtSection, sizeof(NtSection));

    for (i = 0; i < NtHeaders.FileHeader.NumberOfSections; i++) {
        if ((ULONG)Address >= NtSection.VirtualAddress &&
            (ULONG)Address < NtSection.VirtualAddress + NtSection.SizeOfRawData
            ) {
            return NtSectionPointer;
        }
        ++NtSectionPointer;
        uc_mem_read(CoreBlock.uc_handle, NtSectionPointer, &NtSection, sizeof(NtSection));
    }

    return NULL;
}

PVOID
UcRtlAddressInSectionTable(
    IN IMAGE_NT_HEADERS NtHeaders,
    IN PVOID Base,
    IN ULONG Address
)
{
    PIMAGE_SECTION_HEADER NtSection;

    NtSection = UcRtlSectionTableFromVirtualAddress(NtHeaders,
        Base,
        Address
    );
    if (NtSection != NULL) {
        return(((PCHAR)Base + ((ULONG_PTR)Address - NtSection->VirtualAddress) + NtSection->PointerToRawData));
    }
    else {
        return(NULL);
    }
}

PVOID
UcRtlpImageDirectoryEntryToData64(
	IN PVOID Base,
	IN BOOLEAN MappedAsImage,
	IN USHORT DirectoryEntry,
	OUT PULONG Size,
	IMAGE_NT_HEADERS64 NtHeaders
)
{
	ULONG DirectoryAddress;

	if (DirectoryEntry >= NtHeaders.OptionalHeader.NumberOfRvaAndSizes) {
		return NULL;
	}

	if (!(DirectoryAddress = NtHeaders.OptionalHeader.DataDirectory[DirectoryEntry].VirtualAddress)) {
		return NULL;
	}

	if (Base < 0x7FFFFFFFFFFFFFFF) {
		if ((PVOID)((PCHAR)Base + DirectoryAddress) >= 0x7FFFFFFFFFFFFFFF) {
			return NULL;
		}
	}

	*Size = NtHeaders.OptionalHeader.DataDirectory[DirectoryEntry].Size;
	if (MappedAsImage || DirectoryAddress < NtHeaders.OptionalHeader.SizeOfHeaders) {
		return((PVOID)((PCHAR)Base + DirectoryAddress));
	}

	return(UcRtlAddressInSectionTable(NtHeaders, Base, DirectoryAddress));
}

PVOID
UcRtlImageDirectoryEntryToData(
    IN PVOID Base,
    IN BOOLEAN MappedAsImage,
    IN USHORT DirectoryEntry,
    OUT PULONG Size
)
{
    IMAGE_DOS_HEADER DosHeader;
    IMAGE_NT_HEADERS NtHeaders;

    if (LDR_IS_DATAFILE(Base)) {
        Base = LDR_DATAFILE_TO_VIEW(Base);
        MappedAsImage = FALSE;
    }

    uc_mem_read(CoreBlock.uc_handle, Base, &DosHeader, sizeof(DosHeader));
    uc_mem_read(CoreBlock.uc_handle, (ULONG64)Base + DosHeader.e_lfanew, &NtHeaders, sizeof(NtHeaders));

    if (!Base)
        return NULL;

    if (NtHeaders.OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        return (UcRtlpImageDirectoryEntryToData64(Base,
            MappedAsImage,
            DirectoryEntry,
            Size,
            NtHeaders));
        
    }
    else {
        return NULL;
    }
}

VOID
UcRtlCaptureImageExceptionValues(
	IN  PVOID Base,
	OUT PVOID* FunctionTable,
	OUT PULONG TableSize
)
{
	* FunctionTable = UcRtlImageDirectoryEntryToData(Base,
		TRUE,
		IMAGE_DIRECTORY_ENTRY_EXCEPTION,
		TableSize);
}

PRUNTIME_FUNCTION
UcRtlLookupFunctionTable(
    IN PVOID ControlPc,
    OUT PVOID* ImageBase,
    OUT PULONG SizeOfTable
)
{
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
				if (((ULONG_PTR)ControlPc >= (ULONG_PTR)Base) &&
					((ULONG_PTR)ControlPc < Bound)) {

                    printf("DllBase:%p SizeOfImage:%x\n", Entry.DllBase, Entry.SizeOfImage);

                    UcRtlCaptureImageExceptionValues(Base,
						&FunctionTable,
						SizeOfTable);

                    printf("FunctionTable:%p SizeOfTable:%x\n", FunctionTable, *SizeOfTable);
					break;
				}
			}
		}
    }
    *ImageBase = Base;
    return FunctionTable;
}

PRUNTIME_FUNCTION
UcRtlLookupFunctionEntry(
    IN ULONG64 ControlPc,
    OUT PULONG64 ImageBase,
    IN OUT PUNWIND_HISTORY_TABLE HistoryTable OPTIONAL
)
{
    ULONG64 BaseAddress;
    ULONG64 BeginAddress;
    ULONG64 EndAddress;
    PRUNTIME_FUNCTION FunctionEntry = NULL;
    RUNTIME_FUNCTION Function = { 0 };
    PRUNTIME_FUNCTION FunctionTable;
    LONG High;
    ULONG Index;
    LONG Low;
    LONG Middle;
    ULONG RelativePc;
    ULONG SizeOfTable;

    if ((ARGUMENT_PRESENT(HistoryTable)) &&
        (HistoryTable->Search != UNWIND_HISTORY_TABLE_NONE)) {
        HistoryTotal += 1;

        if ((ControlPc >= HistoryTable->LowAddress) &&
            (ControlPc < HistoryTable->HighAddress)) {

            HistorySearch += 1;
            for (Index = 0; Index < HistoryTable->Count; Index += 1) {
                BaseAddress = HistoryTable->Entry[Index].ImageBase;
                FunctionEntry = HistoryTable->Entry[Index].FunctionEntry;
				BeginAddress = EndAddress = 0;
				uc_mem_read(CoreBlock.uc_handle, (ULONG64)FunctionEntry, &BeginAddress, 4);
				uc_mem_read(CoreBlock.uc_handle, (ULONG64)FunctionEntry + 4, &EndAddress, 4);
				BeginAddress += BaseAddress;
				EndAddress += BaseAddress;
                if ((ControlPc >= BeginAddress) && (ControlPc < EndAddress)) {
                    *ImageBase = BaseAddress;
                    HistorySearchHits += 1;
                    return FunctionEntry;
                }
            }
        }
    }

    FunctionTable = UcRtlLookupFunctionTable((PVOID)ControlPc,
        (PVOID*)ImageBase,
        &SizeOfTable);

    if (FunctionTable != NULL) {
        Low = 0;
        High = (SizeOfTable / sizeof(RUNTIME_FUNCTION)) - 1;
        RelativePc = (ULONG)(ControlPc - *ImageBase);
        while (High >= Low) {

            Middle = (Low + High) >> 1;
            FunctionEntry = FunctionTable + Middle;
            uc_mem_read(CoreBlock.uc_handle, FunctionEntry, &Function, sizeof(Function));

            if (RelativePc < Function.BeginAddress) {
                High = Middle - 1;

            }
            else if (RelativePc >= Function.EndAddress) {
                Low = Middle + 1;

            }
            else {
                break;
            }
        }

        if (High < Low) {
            FunctionEntry = NULL;
        }
    }
    else {
        FunctionEntry = NULL;
    }

    if (ARGUMENT_PRESENT(HistoryTable) &&
        (HistoryTable->Search == UNWIND_HISTORY_TABLE_NONE)) {

        HistoryInsert += 1;
    }

    if (FunctionEntry != NULL) {
        if (ARGUMENT_PRESENT(HistoryTable) &&
            (HistoryTable->Search == UNWIND_HISTORY_TABLE_NONE) &&
            (HistoryTable->Count < UNWIND_HISTORY_TABLE_SIZE)) {

            Index = HistoryTable->Count;
            HistoryTable->Count += 1;
            HistoryTable->Entry[Index].ImageBase = *ImageBase;
            HistoryTable->Entry[Index].FunctionEntry = FunctionEntry;
            BeginAddress = Function.BeginAddress + *ImageBase;
            EndAddress = Function.EndAddress + *ImageBase;
            if (BeginAddress < HistoryTable->LowAddress) {
                HistoryTable->LowAddress = BeginAddress;

            }

            if (EndAddress > HistoryTable->HighAddress) {
                HistoryTable->HighAddress = EndAddress;
            }

            HistoryInsertHits += 1;
        }
    }

    return FunctionEntry;
}

PRUNTIME_FUNCTION
UcRtlpUnwindPrologue(
    IN ULONG64 ImageBase,
    IN ULONG64 ControlPc,
    IN ULONG64 FrameBase,
    IN PRUNTIME_FUNCTION FunctionEntryPointer,
    IN OUT PCONTEXT ContextRecord,
    IN OUT PKNONVOLATILE_CONTEXT_POINTERS ContextPointers OPTIONAL
)
{

    PM128A FloatingAddress;
    PM128A FloatingRegister;
    ULONG FrameOffset;
    ULONG Index;
    PULONG64 IntegerAddress = NULL;
    PULONG64 IntegerRegister;
    BOOLEAN MachineFrame;
    ULONG OpInfo;
    ULONG PrologOffset;
    PULONG64 ReturnAddress;
    PULONG64 StackAddress;
    UNWIND_CODE UnwindCode;
    UNWIND_INFO UnwindInfo;
    ULONG UnwindOp;

    RUNTIME_FUNCTION FunctionEntry;
    ULONG64 _IntegerAddress = 0;
    uc_err err1;
    M128A FloatingAddressTemp;

    //
    // Process the unwind codes.
    //

    FloatingRegister = &ContextRecord->Xmm0;
    IntegerRegister = &ContextRecord->Rax;
    Index = 0;
    MachineFrame = FALSE;

    uc_mem_read(CoreBlock.uc_handle, FunctionEntryPointer, &FunctionEntry, sizeof(FunctionEntry));
    uc_mem_read(CoreBlock.uc_handle, FunctionEntry.UnwindData + ImageBase, &UnwindInfo, sizeof(UnwindInfo));

    PrologOffset = (ULONG)(ControlPc - (FunctionEntry.BeginAddress + ImageBase));
 
    while (Index < UnwindInfo.CountOfCodes) {

        //
        // If the prologue offset is greater than the next unwind code offset,
        // then simulate the effect of the unwind code.
        //
		uc_mem_read(
			CoreBlock.uc_handle,
			FunctionEntry.UnwindData + ImageBase + 4 + Index,
			&UnwindCode,
			sizeof(UnwindCode));

        UnwindOp = UnwindCode.UnwindOp;
        OpInfo = UnwindCode.OpInfo;
        if (PrologOffset >= UnwindCode.CodeOffset) {
            switch (UnwindOp) {

                //
                // Push nonvolatile integer register.
                //
                // The operation information is the register number of the
                // register than was pushed.
                //

            case UWOP_PUSH_NONVOL:
                IntegerAddress = (PULONG64)(ContextRecord->Rsp);
				_IntegerAddress = 0;
				err1 = uc_mem_read(
					CoreBlock.uc_handle,
					IntegerAddress,
					&_IntegerAddress,
					sizeof(_IntegerAddress));
				printf("err1:%d\n", err1);
                IntegerRegister[OpInfo] = _IntegerAddress;
                if (ARGUMENT_PRESENT(ContextPointers)) {
                    ContextPointers->IntegerContext[OpInfo] = IntegerAddress;
                }

                ContextRecord->Rsp += 8;
                break;

                //
                // Allocate a large sized area on the stack.
                //
                // The operation information determines if the size is
                // 16- or 32-bits.
                //

            case UWOP_ALLOC_LARGE:
                Index += 1;
                FrameOffset = UnwindCode.FrameOffset;
                if (OpInfo != 0) {
                    Index += 1;
                    FrameOffset += (UnwindCode.FrameOffset << 16);

                }
                else {
                    FrameOffset *= 8;
                }

                ContextRecord->Rsp += FrameOffset;
                break;

                //
                // Allocate a small sized area on the stack.
                //
                // The operation information is the size of the unscaled
                // allocation size (8 is the scale factor) minus 8.
                //

            case UWOP_ALLOC_SMALL:
                ContextRecord->Rsp += (OpInfo * 8) + 8;
                break;

                //
                // Establish the the frame pointer register.
                //
                // The operation information is not used.
                //

            case UWOP_SET_FPREG:
                ContextRecord->Rsp = IntegerRegister[UnwindInfo.FrameRegister];
                ContextRecord->Rsp -= UnwindInfo.FrameOffset * 16;
                break;

                //
                // Save nonvolatile integer register on the stack using a
                // 16-bit displacment.
                //
                // The operation information is the register number.
                //

            case UWOP_SAVE_NONVOL:
                Index += 1;
				uc_mem_read(
					CoreBlock.uc_handle,
					FunctionEntry.UnwindData + ImageBase + 4 + Index,
					&UnwindCode,
					sizeof(UnwindCode));
                FrameOffset = UnwindCode.FrameOffset * 8;
                IntegerAddress = (PULONG64)(FrameBase + FrameOffset);
                err1 = uc_mem_read(
                    CoreBlock.uc_handle,
                    IntegerAddress,
                    &_IntegerAddress,
                    sizeof(_IntegerAddress));
                printf("err1:%d\n", err1);
                IntegerRegister[OpInfo] = _IntegerAddress;
                if (ARGUMENT_PRESENT(ContextPointers)) {
                    ContextPointers->IntegerContext[OpInfo] = IntegerAddress;
                }

                break;

                //
                // Save nonvolatile integer register on the stack using a
                // 32-bit displacment.
                //
                // The operation information is the register number.
                //

            case UWOP_SAVE_NONVOL_FAR:
                Index += 2;
                uc_mem_read(
                    CoreBlock.uc_handle,
                    FunctionEntry.UnwindData + ImageBase + 4 + (Index - 1),
					&UnwindCode,
					sizeof(UnwindCode));
                FrameOffset = UnwindCode.FrameOffset;
                FrameOffset += (UnwindCode.FrameOffset << 16);
				err1 = uc_mem_read(
					CoreBlock.uc_handle,
					IntegerAddress,
					&_IntegerAddress,
					sizeof(_IntegerAddress));
				printf("err1:%d\n", err1);
                IntegerRegister[OpInfo] = _IntegerAddress;
                if (ARGUMENT_PRESENT(ContextPointers)) {
                    ContextPointers->IntegerContext[OpInfo] = IntegerAddress;
                }

                break;

                //
                // Save a nonvolatile XMM(64) register on the stack using a
                // 16-bit displacement.
                //
                // The operation information is the register number.
                //

            case UWOP_SAVE_XMM:
                Index += 1;
				uc_mem_read(
					CoreBlock.uc_handle,
					FunctionEntry.UnwindData + ImageBase + 4 + (Index),
					&UnwindCode,
					sizeof(UnwindCode));
                FrameOffset = UnwindCode.FrameOffset * 8;
                FloatingAddress = (PM128A)(FrameBase + FrameOffset);
				err1 = uc_mem_read(
					CoreBlock.uc_handle,
                    FloatingAddress,
					&FloatingAddressTemp,
					sizeof(FloatingAddressTemp));
				printf("err1:%d\n", err1);
                FloatingRegister[OpInfo].Low = FloatingAddressTemp.Low;
                FloatingRegister[OpInfo].High = 0;
                if (ARGUMENT_PRESENT(ContextPointers)) {
                    ContextPointers->FloatingContext[OpInfo] = FloatingAddress;
                }

                break;

                //
                // Save a nonvolatile XMM(64) register on the stack using a
                // 32-bit displacement.
                //
                // The operation information is the register number.
                //

            case UWOP_SAVE_XMM_FAR:
                Index += 2;
				uc_mem_read(
					CoreBlock.uc_handle,
					FunctionEntry.UnwindData + ImageBase + 4 + (Index - 1),
					&UnwindCode,
					sizeof(UnwindCode));
                FrameOffset = UnwindCode.FrameOffset;
                FrameOffset += (UnwindCode.FrameOffset << 16);
                FloatingAddress = (PM128A)(FrameBase + FrameOffset);
				err1 = uc_mem_read(
					CoreBlock.uc_handle,
					FloatingAddress,
					&FloatingAddressTemp,
					sizeof(FloatingAddressTemp));
				printf("err1:%d\n", err1);
                FloatingRegister[OpInfo].Low = FloatingAddressTemp.Low;
                FloatingRegister[OpInfo].High = 0;
                if (ARGUMENT_PRESENT(ContextPointers)) {
                    ContextPointers->FloatingContext[OpInfo] = FloatingAddress;
                }

                break;

                //
                // Save a nonvolatile XMM(128) register on the stack using a
                // 16-bit displacement.
                //
                // The operation information is the register number.
                //

            case UWOP_SAVE_XMM128:
                Index += 1;
				uc_mem_read(
					CoreBlock.uc_handle,
					FunctionEntry.UnwindData + ImageBase + 4 + (Index),
					&UnwindCode,
					sizeof(UnwindCode));
                FrameOffset = UnwindCode.FrameOffset * 16;
                FloatingAddress = (PM128A)(FrameBase + FrameOffset);
				err1 = uc_mem_read(
					CoreBlock.uc_handle,
					FloatingAddress,
					&FloatingAddressTemp,
					sizeof(FloatingAddressTemp));
				printf("err1:%d\n", err1);
                FloatingRegister[OpInfo].Low = FloatingAddressTemp.Low;
                FloatingRegister[OpInfo].High = FloatingAddressTemp.High;
                if (ARGUMENT_PRESENT(ContextPointers)) {
                    ContextPointers->FloatingContext[OpInfo] = FloatingAddress;
                }

                break;

                //
                // Save a nonvolatile XMM(128) register on the stack using a
                // 32-bit displacement.
                //
                // The operation information is the register number.
                //

            case UWOP_SAVE_XMM128_FAR:
                Index += 2;
                uc_mem_read(
                    CoreBlock.uc_handle,
                    FunctionEntry.UnwindData + ImageBase + 4 + (Index - 1),
					&UnwindCode,
					sizeof(UnwindCode));
                FrameOffset = UnwindCode.FrameOffset;
                FrameOffset += (UnwindCode.FrameOffset << 16);
                FloatingAddress = (PM128A)(FrameBase + FrameOffset);
				err1 = uc_mem_read(
					CoreBlock.uc_handle,
					FloatingAddress,
					&FloatingAddressTemp,
					sizeof(FloatingAddressTemp));
				printf("err1:%d\n", err1);
                FloatingRegister[OpInfo].Low = FloatingAddressTemp.Low;
                FloatingRegister[OpInfo].High = FloatingAddressTemp.High;
                if (ARGUMENT_PRESENT(ContextPointers)) {
                    ContextPointers->FloatingContext[OpInfo] = FloatingAddress;
                }

                break;

                //
                // Push a machine frame on the stack.
                //
                // The operation information determines whether the machine
                // frame contains an error code or not.
                //

            case UWOP_PUSH_MACHFRAME:
                MachineFrame = TRUE;
                ReturnAddress = (PULONG64)(ContextRecord->Rsp);
                StackAddress = (PULONG64)(ContextRecord->Rsp + (3 * 8));
                if (OpInfo != 0) {
                    ReturnAddress += 1;
                    StackAddress += 1;
                }

                ContextRecord->Rip = *ReturnAddress;
                ContextRecord->Rsp = *StackAddress;
                break;

                //
                // Unused codes.
                //

            default:
                break;
            }

            Index += 1;

        }
        else {

            //
            // Skip this unwind operation by advancing the slot index by the
            // number of slots consumed by this operation.
            //

            Index += RtlpUnwindOpSlotTable[UnwindOp];

            //
            // Special case any unwind operations that can consume a variable
            // number of slots.
            // 

            switch (UnwindOp) {

                //
                // A non-zero operation information indicates that an
                // additional slot is consumed.
                //

            case UWOP_ALLOC_LARGE:
                if (OpInfo != 0) {
                    Index += 1;
                }

                break;

                //
                // No other special cases.
                //

            default:
                break;
            }
        }
    }

    //
    // If chained unwind information is specified, then recursively unwind
    // the chained information. Otherwise, determine the return address if
    // a machine frame was not encountered during the scan of the unwind
    // codes.
    //

    if ((UnwindInfo.Flags & UNW_FLAG_CHAININFO) != 0) {
        Index = UnwindInfo.CountOfCodes;
        if ((Index & 1) != 0) {
            Index += 1;
        }

        ULONG Temp = 0;
		uc_mem_read(
			CoreBlock.uc_handle,
			FunctionEntry.UnwindData + ImageBase + 4 + (Index),
			&Temp,
			sizeof(Temp));
        FunctionEntryPointer = (PRUNTIME_FUNCTION)(Temp + ImageBase);
        return UcRtlpUnwindPrologue(ImageBase,
            ControlPc,
            FrameBase,
            FunctionEntryPointer,
            ContextRecord,
            ContextPointers);

    }
    else {
        if (MachineFrame == FALSE) {
 //           ContextRecord->Rip = *(PULONG64)(ContextRecord->Rsp);
            uc_mem_read(CoreBlock.uc_handle, ContextRecord->Rsp, &ContextRecord->Rip, sizeof(ContextRecord->Rip));
            ContextRecord->Rsp += 8;
        }

        return FunctionEntryPointer;
    }
}

PEXCEPTION_ROUTINE
UcRtlVirtualUnwind(
    IN ULONG HandlerType,
    IN ULONG64 ImageBase,
    IN ULONG64 ControlPc,
    IN PRUNTIME_FUNCTION FunctionEntryPointer,
    IN OUT PCONTEXT ContextRecord,
    OUT PVOID* HandlerData,
    OUT PULONG64 EstablisherFrame,
    IN OUT PKNONVOLATILE_CONTEXT_POINTERS ContextPointers OPTIONAL
)
{
    ULONG64 BranchTarget;
    LONG Displacement;
    ULONG FrameRegister;
    ULONG Index;
    LOGICAL InEpilogue;
    PULONG64 IntegerAddress;
    PULONG64 IntegerRegister;
    PUCHAR NextByte;
    UCHAR Byte[9];
    ULONG PrologOffset;
    ULONG RegisterNumber;
    UNWIND_INFO UnwindInfo;
    RUNTIME_FUNCTION FunctionEntry;
    UNWIND_CODE UnwindCode;

    uc_mem_read(CoreBlock.uc_handle, FunctionEntryPointer, &FunctionEntry, sizeof(FunctionEntry));
    uc_mem_read(CoreBlock.uc_handle, FunctionEntry.UnwindData + ImageBase, &UnwindInfo, sizeof(UnwindInfo));

    PrologOffset = (ULONG)(ControlPc - (FunctionEntry.BeginAddress + ImageBase));
    if (UnwindInfo.FrameRegister == 0) {
        *EstablisherFrame = ContextRecord->Rsp;

    }
    else if ((PrologOffset >= UnwindInfo.SizeOfProlog) ||
        ((UnwindInfo.Flags & UNW_FLAG_CHAININFO) != 0)) {
        *EstablisherFrame = (&ContextRecord->Rax)[UnwindInfo.FrameRegister];
        *EstablisherFrame -= UnwindInfo.FrameOffset * 16;

    }
    else {
        Index = 0;
        while (Index < UnwindInfo.CountOfCodes) {
            uc_mem_read(
                CoreBlock.uc_handle,
                FunctionEntry.UnwindData + ImageBase + 4 + Index,
                &UnwindCode,
                sizeof(UnwindCode));
            if (UnwindCode.UnwindOp == UWOP_SET_FPREG) {
                break;
            }

            Index += 1;
        }
		uc_mem_read(
			CoreBlock.uc_handle,
			FunctionEntry.UnwindData + ImageBase + 4 + Index,
			&UnwindCode,
			sizeof(UnwindCode));
        if (PrologOffset >= UnwindCode.CodeOffset) {
            *EstablisherFrame = (&ContextRecord->Rax)[UnwindInfo.FrameRegister];
            *EstablisherFrame -= UnwindInfo.FrameOffset * 16;

        }
        else {
            *EstablisherFrame = ContextRecord->Rsp;
        }
    }

    IntegerRegister = &ContextRecord->Rax;
    NextByte = (PUCHAR)ControlPc;

    //
    // Check for one of:
    //
    //   add rsp, imm8
    //       or
    //   add rsp, imm32
    //       or
    //   lea rsp, -disp8[fp]
    //       or
    //   lea rsp, -disp32[fp]
    //
    uc_mem_read(CoreBlock.uc_handle, NextByte, Byte, sizeof(Byte));
    if ((Byte[0] == SIZE64_PREFIX) &&
        (Byte[1] == ADD_IMM8_OP) &&
        (Byte[2] == 0xc4)) {

        //
        // add rsp, imm8.
        //

        NextByte += 4;

    }

    else if ((Byte[0] == SIZE64_PREFIX) &&
        (Byte[1] == ADD_IMM32_OP) &&
        (Byte[2] == 0xc4)) {

        //
        // add rsp, imm32.
        //

        NextByte += 7;

    }
    else if (((Byte[0] & 0xf8) == SIZE64_PREFIX) &&
        (Byte[1] == LEA_OP)) {

        FrameRegister = ((Byte[0] & 0x7) << 3) | (Byte[2] & 0x7);
        if ((FrameRegister != 0) &&
            (FrameRegister == UnwindInfo.FrameRegister)) {
            if ((Byte[2] & 0xf8) == 0x60) {

                //
                // lea rsp, disp8[fp].
                //

                NextByte += 4;

            }
            else if ((Byte[2] & 0xf8) == 0xa0) {

                //
                // lea rsp, disp32[fp].
                //

                NextByte += 7;
            }
        }
    }

    //
    // Check for any number of:
    //
    //   pop nonvolatile-integer-register[0..15].
    //

    while (TRUE) {
        uc_mem_read(CoreBlock.uc_handle, NextByte, Byte, sizeof(Byte));
        if ((Byte[0] & 0xf8) == POP_OP) {
            NextByte += 1;

        }
        else if (((Byte[0] & 0xf8) == SIZE64_PREFIX) &&
            ((Byte[1] & 0xf8) == POP_OP)) {

            NextByte += 2;

        }
        else {
            break;
        }
    }

    //
    // If the next instruction is a return, then control is currently in
    // an epilogue and execution of the epilogue should be emulated.
    // Otherwise, execution is not in an epilogue and the prologue should
    // be unwound.
    //

    InEpilogue = FALSE;
    uc_mem_read(CoreBlock.uc_handle, NextByte, Byte, sizeof(Byte));
    if (Byte[0] == RET_OP) {

        //
        // A return is an unambiguous indication of an epilogue
        //

        InEpilogue = TRUE;

    }
    else if (Byte[0] == JMP_IMM8_OP || Byte[0] == JMP_IMM32_OP) {

        //
        // An unconditional branch to a target that is equal to the start of
        // or outside of this routine is logically a call to another function.
        // 

        BranchTarget = (ULONG64)NextByte - ImageBase;
        if (Byte[0] == JMP_IMM8_OP) {
            BranchTarget += 2 + (CHAR)Byte[1];

        }
        else {
            BranchTarget += 5 + *((LONG UNALIGNED*) & Byte[1]);
        }

        //
        // Now determine whether the branch target refers to code within this
        // function. If not, then it is an epilogue indicator.
        //

        if (BranchTarget <= FunctionEntry.BeginAddress ||
            BranchTarget > FunctionEntry.EndAddress) {

            InEpilogue = TRUE;
        }
    }

    if (InEpilogue != FALSE) {
        NextByte = (PUCHAR)ControlPc;

        //
        // Emulate one of (if any):
        //
        //   add rsp, imm8
        //       or
        //   add rsp, imm32
        //       or                
        //   lea rsp, disp8[frame-register]
        //       or
        //   lea rsp, disp32[frame-register]
        //
        uc_mem_read(CoreBlock.uc_handle, NextByte, Byte, sizeof(Byte));
        if ((Byte[0] & 0xf8) == SIZE64_PREFIX) {

            if (Byte[1] == ADD_IMM8_OP) {

                //
                // add rsp, imm8.
                //

                ContextRecord->Rsp += (CHAR)Byte[3];
                NextByte += 4;

            }
            else if (Byte[1] == ADD_IMM32_OP) {

                //
                // add rsp, imm32.
                //

                Displacement = Byte[3] | (Byte[4] << 8);
                Displacement |= (Byte[5] << 16) | (Byte[6] << 24);
                ContextRecord->Rsp += Displacement;
                NextByte += 7;

            }
            else if (Byte[1] == LEA_OP) {
                if ((Byte[2] & 0xf8) == 0x60) {

                    //
                    // lea rsp, disp8[frame-register].
                    //

                    ContextRecord->Rsp = IntegerRegister[FrameRegister];
                    ContextRecord->Rsp += (CHAR)Byte[3];
                    NextByte += 4;

                }
                else if ((Byte[2] & 0xf8) == 0xa0) {

                    //
                    // lea rsp, disp32[frame-register].
                    //

                    Displacement = Byte[3] | (Byte[4] << 8);
                    Displacement |= (Byte[5] << 16) | (Byte[6] << 24);
                    ContextRecord->Rsp = IntegerRegister[FrameRegister];
                    ContextRecord->Rsp += Displacement;
                    NextByte += 7;
                }
            }
        }

        //
        // Emulate any number of (if any):
        //
        //   pop nonvolatile-integer-register.
        //

        while (TRUE) {
            uc_mem_read(CoreBlock.uc_handle, NextByte, Byte, sizeof(Byte));
            if ((Byte[0] & 0xf8) == POP_OP) {

                //
                // pop nonvolatile-integer-register[0..7]
                //

                RegisterNumber = Byte[0] & 0x7;
                IntegerAddress = (PULONG64)ContextRecord->Rsp;
                IntegerRegister[RegisterNumber] = *IntegerAddress;
                if (ARGUMENT_PRESENT(ContextPointers)) {
                    ContextPointers->IntegerContext[RegisterNumber] = IntegerAddress;
                }

                ContextRecord->Rsp += 8;
                NextByte += 1;

            }
            else if (((Byte[0] & 0xf8) == SIZE64_PREFIX) &&
                ((Byte[1] & 0xf8) == POP_OP)) {

                //
                // pop nonvolatile-integer-regiser[8..15]
                //

                RegisterNumber = ((Byte[0] & 1) << 3) | (Byte[1] & 0x7);
                IntegerAddress = (PULONG64)ContextRecord->Rsp;
                IntegerRegister[RegisterNumber] = *IntegerAddress;
                if (ARGUMENT_PRESENT(ContextPointers)) {
                    ContextPointers->IntegerContext[RegisterNumber] = IntegerAddress;
                }

                ContextRecord->Rsp += 8;
                NextByte += 2;

            }
            else {
                break;
            }
        }

        //
        // Emulate return and return null exception handler.
        //
        // Note: this instruction might in fact be a jmp, however
        //       we want to emulate a return regardless.
        //

        ContextRecord->Rip = *(PULONG64)(ContextRecord->Rsp);
        ContextRecord->Rsp += 8;
        return NULL;
    }

    //
    // Control left the specified function outside an epilogue. Unwind the
    // subject function and any chained unwind information.
    //

    FunctionEntryPointer = UcRtlpUnwindPrologue(ImageBase,
        ControlPc,
        *EstablisherFrame,
        FunctionEntryPointer,
        ContextRecord,
        ContextPointers);

    //
    // If control left the specified function outside of the prologue and
    // the function has a handler that matches the specified type, then
    // return the address of the language specific exception handler.
    // Otherwise, return NULL.
    //

    uc_mem_read(CoreBlock.uc_handle, FunctionEntry.UnwindData + ImageBase, &UnwindInfo, sizeof(UnwindInfo));
    PrologOffset = (ULONG)(ControlPc - (FunctionEntry.BeginAddress + ImageBase));
    if ((PrologOffset >= UnwindInfo.SizeOfProlog) &&
        ((UnwindInfo.Flags & HandlerType) != 0)) {
        Index = UnwindInfo.CountOfCodes;
        if ((Index & 1) != 0) {
            Index += 1;
        }
        *HandlerData = (PUNWIND_CODE)(FunctionEntry.UnwindData + ImageBase + 4) + Index + 2;
        
        ULONG Temp = 0;
        uc_mem_read(
            CoreBlock.uc_handle,
            (PUNWIND_CODE)(FunctionEntry.UnwindData + ImageBase + 4) + Index,
            &Temp,
            sizeof(Temp));

        return (PEXCEPTION_ROUTINE)(Temp + ImageBase);

    }
    else {
        return NULL;
    }
}

PUNWIND_INFO RtlpLookupPrimaryUnwindInfo(
	IN PRUNTIME_FUNCTION FunctionEntry,
	IN ULONG64 ImageBase,
	OUT PRUNTIME_FUNCTION* PrimaryEntry
)
{

	ULONG Index;
	PUNWIND_INFO UnwindInfo;
	RUNTIME_FUNCTION FunctionEntryCell;
	uc_mem_read(CoreBlock.uc_handle, (uint64_t)FunctionEntry, &FunctionEntryCell, sizeof(FunctionEntryCell));

	//
	// Locate the unwind information and determine whether it is chained.
	// If the unwind information is chained, then locate the parent function
	// entry and loop again.
	//

	do {
		UnwindInfo = (PUNWIND_INFO)(FunctionEntryCell.UnwindData + ImageBase);

		ULONG64 m_cbSize = offsetof(UNWIND_INFO, UnwindCode);
		PVOID m_pBuffer = malloc(m_cbSize);

		uc_mem_read(CoreBlock.uc_handle, (uint64_t)UnwindInfo, m_pBuffer, m_cbSize);
		PUNWIND_INFO UnwindInfoCellPtr = (PUNWIND_INFO)m_pBuffer;

		m_cbSize = offsetof(UNWIND_INFO, UnwindCode) + UnwindInfoCellPtr->CountOfCodes * sizeof(UNWIND_CODE);
		m_pBuffer = realloc(m_pBuffer, m_cbSize);

		uc_mem_read(CoreBlock.uc_handle, (uint64_t)UnwindInfo, m_pBuffer, m_cbSize);
		UnwindInfoCellPtr = (PUNWIND_INFO)m_pBuffer;

		if ((UnwindInfoCellPtr->Flags & UNW_FLAG_CHAININFO) == 0) {
			break;
		}

		Index = UnwindInfoCellPtr->CountOfCodes;
		if ((Index & 1) != 0) {
			Index += 1;
		}

		FunctionEntry = (PRUNTIME_FUNCTION)&UnwindInfoCellPtr->UnwindCode[Index];
	} while (TRUE);

	*PrimaryEntry = FunctionEntry;
	return UnwindInfo;
}


PRUNTIME_FUNCTION RtlpSameFunction(
	IN PRUNTIME_FUNCTION FunctionEntry,
	IN ULONG64 ImageBase,
	IN ULONG64 ControlPc
)
{

	PRUNTIME_FUNCTION PrimaryFunctionEntry;
	PRUNTIME_FUNCTION TargetFunctionEntry;
	ULONG64 TargetImageBase;
	PUNWIND_INFO UnwindInfo1;
	PUNWIND_INFO UnwindInfo2;

	//
	// Lookup the primary function entry associated with the specified
	// function entry.
	// 

	UnwindInfo1 = RtlpLookupPrimaryUnwindInfo(FunctionEntry,
		ImageBase,
		&PrimaryFunctionEntry);

	//
	// Determine the function entry containing the control Pc and similarly
	// resolve its primary function entry.  If no function entry can be
	// found then the control pc resides in a different function.
	//

	TargetFunctionEntry = UcRtlLookupFunctionEntry(ControlPc,
		&TargetImageBase,
		NULL);

	if (TargetFunctionEntry == NULL) {
		return NULL;
	}

	//
	// Lookup the primary function entry associated with the target function
	// entry.
	//

	UnwindInfo2 = RtlpLookupPrimaryUnwindInfo(TargetFunctionEntry,
		TargetImageBase,
		&PrimaryFunctionEntry);

	//
	// If the address of the two sets of unwind information are equal, then
	// return the address of the primary function entry. Otherwise, return
	// NULL.
	//

	if (UnwindInfo1 == UnwindInfo2) {
		return PrimaryFunctionEntry;

	}
	else {
		return NULL;
	}
}

PRUNTIME_FUNCTION RtlpUnwindPrologue(
	IN ULONG64 ImageBase,
	IN ULONG64 ControlPc,
	IN ULONG64 FrameBase,
	IN PRUNTIME_FUNCTION FunctionEntry,
	IN OUT PCONTEXT ContextRecord,
	IN OUT PKNONVOLATILE_CONTEXT_POINTERS ContextPointers OPTIONAL
)
{

	PM128A FloatingAddress;
	PM128A FloatingRegister;
	ULONG FrameOffset;
	ULONG Index;
	PULONG64 IntegerAddress;
	PULONG64 IntegerRegister;
	BOOLEAN MachineFrame;
	ULONG OpInfo;
	ULONG PrologOffset;
	PULONG64 ReturnAddress;
	PULONG64 StackAddress;
	PUNWIND_INFO UnwindInfo;
	ULONG UnwindOp;
	uint64_t ValueFromAddress;

	//
	// Process the unwind codes.
	//

	FloatingRegister = &ContextRecord->Xmm0;
	IntegerRegister = &ContextRecord->Rax;
	Index = 0;
	MachineFrame = FALSE;

	RUNTIME_FUNCTION FunctionEntryCell;
	uc_mem_read(CoreBlock.uc_handle, (uint64_t)FunctionEntry, &FunctionEntryCell, sizeof(FunctionEntryCell));

	PrologOffset = (ULONG)(ControlPc - (FunctionEntryCell.BeginAddress + ImageBase));
	UnwindInfo = (PUNWIND_INFO)(FunctionEntryCell.UnwindData + ImageBase);

	ULONG64 m_cbSize = offsetof(UNWIND_INFO, UnwindCode);
	PVOID m_pBuffer = malloc(m_cbSize);

	uc_mem_read(CoreBlock.uc_handle, (uint64_t)UnwindInfo, m_pBuffer, m_cbSize);
	PUNWIND_INFO UnwindInfoCellPtr = (PUNWIND_INFO)m_pBuffer;

	m_cbSize = offsetof(UNWIND_INFO, UnwindCode) + UnwindInfoCellPtr->CountOfCodes * sizeof(UNWIND_CODE) + sizeof(DWORD) * 2;
	m_pBuffer = realloc(m_pBuffer, m_cbSize);

	uc_mem_read(CoreBlock.uc_handle, (uint64_t)UnwindInfo, m_pBuffer, m_cbSize);
	UnwindInfoCellPtr = (PUNWIND_INFO)m_pBuffer;

	while (Index < UnwindInfoCellPtr->CountOfCodes) {

		//
		// If the prologue offset is greater than the next unwind code offset,
		// then simulate the effect of the unwind code.
		//

		UnwindOp = UnwindInfoCellPtr->UnwindCode[Index].UnwindOp;
		OpInfo = UnwindInfoCellPtr->UnwindCode[Index].OpInfo;
		if (PrologOffset >= UnwindInfoCellPtr->UnwindCode[Index].CodeOffset) {
			switch (UnwindOp) {

				//
				// Push nonvolatile integer register.
				//
				// The operation information is the register number of the
				// register than was pushed.
				//

			case UWOP_PUSH_NONVOL:
				IntegerAddress = (PULONG64)(ContextRecord->Rsp);

				uc_mem_read(CoreBlock.uc_handle, (uint64_t)IntegerAddress, &ValueFromAddress, sizeof(ValueFromAddress));

				IntegerRegister[OpInfo] = ValueFromAddress;
				if (ContextPointers) {
					ContextPointers->IntegerContext[OpInfo] = IntegerAddress;
				}

				ContextRecord->Rsp += 8;
				break;

				//
				// Allocate a large sized area on the stack.
				//
				// The operation information determines if the size is
				// 16- or 32-bits.
				//

			case UWOP_ALLOC_LARGE:
				Index += 1;
				FrameOffset = UnwindInfoCellPtr->UnwindCode[Index].FrameOffset;
				if (OpInfo != 0) {
					Index += 1;
					FrameOffset += (UnwindInfoCellPtr->UnwindCode[Index].FrameOffset << 16);

				}
				else {
					FrameOffset *= 8;
				}

				ContextRecord->Rsp += FrameOffset;
				break;

				//
				// Allocate a small sized area on the stack.
				//
				// The operation information is the size of the unscaled
				// allocation size (8 is the scale factor) minus 8.
				//

			case UWOP_ALLOC_SMALL:
				ContextRecord->Rsp += (OpInfo * 8) + 8;
				break;

				//
				// Establish the the frame pointer register.
				//
				// The operation information is not used.
				//

			case UWOP_SET_FPREG:
				ContextRecord->Rsp = IntegerRegister[UnwindInfoCellPtr->FrameRegister];
				ContextRecord->Rsp -= UnwindInfoCellPtr->FrameOffset * 16;
				break;

				//
				// Save nonvolatile integer register on the stack using a
				// 16-bit displacment.
				//
				// The operation information is the register number.
				//

			case UWOP_SAVE_NONVOL:
				Index += 1;
				FrameOffset = UnwindInfoCellPtr->UnwindCode[Index].FrameOffset * 8;
				IntegerAddress = (PULONG64)(FrameBase + FrameOffset);

				uc_mem_read(CoreBlock.uc_handle, (uint64_t)IntegerAddress, &ValueFromAddress, sizeof(ValueFromAddress));

				IntegerRegister[OpInfo] = ValueFromAddress;
				if (ContextPointers) {
					ContextPointers->IntegerContext[OpInfo] = IntegerAddress;
				}

				break;

				//
				// Save nonvolatile integer register on the stack using a
				// 32-bit displacment.
				//
				// The operation information is the register number.
				//

			case UWOP_SAVE_NONVOL_FAR:
				Index += 2;
				FrameOffset = UnwindInfoCellPtr->UnwindCode[Index - 1].FrameOffset;
				FrameOffset += (UnwindInfoCellPtr->UnwindCode[Index].FrameOffset << 16);
				IntegerAddress = (PULONG64)(FrameBase + FrameOffset);
				uc_mem_read(CoreBlock.uc_handle, (uint64_t)IntegerAddress, &ValueFromAddress, sizeof(ValueFromAddress));
				IntegerRegister[OpInfo] = ValueFromAddress;
				if (ContextPointers) {
					ContextPointers->IntegerContext[OpInfo] = IntegerAddress;
				}

				break;

				//
				// Spare unused codes.
				//

			case UWOP_SAVE_XMM:
			case UWOP_SAVE_XMM_FAR:

				break;

				//
				// Save a nonvolatile XMM(128) register on the stack using a
				// 16-bit displacement.
				//
				// The operation information is the register number.
				//

			case UWOP_SAVE_XMM128:
				Index += 1;
				FrameOffset = UnwindInfoCellPtr->UnwindCode[Index].FrameOffset * 16;
				FloatingAddress = (PM128A)(FrameBase + FrameOffset);
				FloatingRegister[OpInfo].Low = FloatingAddress->Low;
				FloatingRegister[OpInfo].High = FloatingAddress->High;
				if (ContextPointers) {
					ContextPointers->FloatingContext[OpInfo] = FloatingAddress;
				}

				break;

				//
				// Save a nonvolatile XMM(128) register on the stack using a
				// 32-bit displacement.
				//
				// The operation information is the register number.
				//

			case UWOP_SAVE_XMM128_FAR:
				Index += 2;
				FrameOffset = UnwindInfoCellPtr->UnwindCode[Index - 1].FrameOffset;
				FrameOffset += (UnwindInfoCellPtr->UnwindCode[Index].FrameOffset << 16);
				FloatingAddress = (PM128A)(FrameBase + FrameOffset);
				FloatingRegister[OpInfo].Low = FloatingAddress->Low;
				FloatingRegister[OpInfo].High = FloatingAddress->High;
				if (ContextPointers) {
					ContextPointers->FloatingContext[OpInfo] = FloatingAddress;
				}

				break;

				//
				// Push a machine frame on the stack.
				//
				// The operation information determines whether the machine
				// frame contains an error code or not.
				//

			case UWOP_PUSH_MACHFRAME:
				MachineFrame = TRUE;
				ReturnAddress = (PULONG64)(ContextRecord->Rsp);
				StackAddress = (PULONG64)(ContextRecord->Rsp + (3 * 8));
				if (OpInfo != 0) {
					ReturnAddress += 1;
					StackAddress += 1;
				}

				uc_mem_read(CoreBlock.uc_handle, (uint64_t)ReturnAddress, &ValueFromAddress, sizeof(ValueFromAddress));

				ContextRecord->Rip = ValueFromAddress;

				uc_mem_read(CoreBlock.uc_handle, (uint64_t)StackAddress, &ValueFromAddress, sizeof(ValueFromAddress));

				ContextRecord->Rsp = ValueFromAddress;
				break;

				//
				// Unused codes.
				//

			default:

				break;
			}

			Index += 1;

		}
		else {

			//
			// Skip this unwind operation by advancing the slot index by the
			// number of slots consumed by this operation.
			//

			Index += RtlpUnwindOpSlotTable[UnwindOp];

			//
			// Special case any unwind operations that can consume a variable
			// number of slots.
			// 

			switch (UnwindOp) {

				//
				// A non-zero operation information indicates that an
				// additional slot is consumed.
				//

			case UWOP_ALLOC_LARGE:
				if (OpInfo != 0) {
					Index += 1;
				}

				break;

				//
				// No other special cases.
				//

			default:
				break;
			}
		}
	}

	//
	// If chained unwind information is specified, then recursively unwind
	// the chained information. Otherwise, determine the return address if
	// a machine frame was not encountered during the scan of the unwind
	// codes.
	//

	if ((UnwindInfoCellPtr->Flags & UNW_FLAG_CHAININFO) != 0) {
		Index = UnwindInfoCellPtr->CountOfCodes;
		if ((Index & 1) != 0) {
			Index += 1;
		}

		FunctionEntry = (PRUNTIME_FUNCTION)(&UnwindInfoCellPtr->UnwindCode[Index]);
		return RtlpUnwindPrologue(ImageBase,
			ControlPc,
			FrameBase,
			FunctionEntry,
			ContextRecord,
			ContextPointers);

	}
	else {
		if (MachineFrame == FALSE) {

			uint64_t ValueFromAddress;
			uc_mem_read(CoreBlock.uc_handle, (uint64_t)ContextRecord->Rsp, &ValueFromAddress, sizeof(ValueFromAddress));

			ContextRecord->Rip = ValueFromAddress;
			ContextRecord->Rsp += 8;
		}

		return FunctionEntry;
	}
}

PEXCEPTION_ROUTINE RtlpVirtualUnwind(
	IN ULONG HandlerType,
	IN ULONG64 ImageBase,
	IN ULONG64 ControlPc,
	IN PRUNTIME_FUNCTION FunctionEntry,
	IN OUT PCONTEXT ContextRecord,
	OUT PVOID* HandlerData,
	OUT PULONG64 EstablisherFrame,
	IN OUT PKNONVOLATILE_CONTEXT_POINTERS ContextPointers OPTIONAL
)
{
	//
	// Define opcode and prefix values.
	//

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

	ULONG64 BranchTarget;
	LONG Displacement;
	ULONG FrameRegister;
	ULONG Index;
	bool InEpilogue;
	PULONG64 IntegerAddress;
	PULONG64 IntegerRegister;
	PUCHAR NextByte;
	PRUNTIME_FUNCTION PrimaryFunctionEntry;
	ULONG PrologOffset;
	ULONG RegisterNumber;
	PUNWIND_INFO UnwindInfo;
	uint64_t ValueFromAddress;

	RUNTIME_FUNCTION FunctionEntryCell;
	uc_mem_read(CoreBlock.uc_handle, (uint64_t)FunctionEntry, &FunctionEntryCell, sizeof(FunctionEntryCell));

	UnwindInfo = (PUNWIND_INFO)(FunctionEntryCell.UnwindData + ImageBase);
	PrologOffset = (ULONG)(ControlPc - (FunctionEntryCell.BeginAddress + ImageBase));

	ULONG64 m_cbSize = offsetof(UNWIND_INFO, UnwindCode);
	PVOID m_pBuffer = malloc(m_cbSize);

	uc_mem_read(CoreBlock.uc_handle, (uint64_t)UnwindInfo, m_pBuffer, m_cbSize);
	PUNWIND_INFO UnwindInfoCellPtr = (PUNWIND_INFO)m_pBuffer;

	m_cbSize = offsetof(UNWIND_INFO, UnwindCode) + UnwindInfoCellPtr->CountOfCodes * sizeof(UNWIND_CODE) + sizeof(DWORD) * 2;
	m_pBuffer = realloc(m_pBuffer, m_cbSize);

	uc_mem_read(CoreBlock.uc_handle, (uint64_t)UnwindInfo, m_pBuffer, m_cbSize);
	UnwindInfoCellPtr = (PUNWIND_INFO)m_pBuffer;

	if (UnwindInfoCellPtr->FrameRegister == 0) {
		*EstablisherFrame = ContextRecord->Rsp;

	}
	else if ((PrologOffset >= UnwindInfoCellPtr->SizeOfProlog) ||
		((UnwindInfoCellPtr->Flags & UNW_FLAG_CHAININFO) != 0)) {

		*EstablisherFrame = (&ContextRecord->Rax)[UnwindInfoCellPtr->FrameRegister];
		*EstablisherFrame -= UnwindInfoCellPtr->FrameOffset * 16;

	}
	else {
		Index = 0;
		while (Index < UnwindInfo->CountOfCodes) {
			if (UnwindInfoCellPtr->UnwindCode[Index].UnwindOp == UWOP_SET_FPREG) {
				break;
			}

			Index += 1;
		}

		if (PrologOffset >= UnwindInfoCellPtr->UnwindCode[Index].CodeOffset) {
			*EstablisherFrame = (&ContextRecord->Rax)[UnwindInfoCellPtr->FrameRegister];
			*EstablisherFrame -= UnwindInfoCellPtr->FrameOffset * 16;

		}
		else {
			*EstablisherFrame = ContextRecord->Rsp;
		}
	}

	//
	// If the point at which control left the specified function is in an
	// epilogue, then emulate the execution of the epilogue forward and
	// return no exception handler.
	//

	IntegerRegister = &ContextRecord->Rax;

	NextByte = (PUCHAR)ControlPc;

	UCHAR NextByteBuffer[15];
	uc_mem_read(CoreBlock.uc_handle, (uint64_t)NextByte, NextByteBuffer, sizeof(NextByteBuffer));
	//
	// Check for one of:
	//
	//   add rsp, imm8
	//       or
	//   add rsp, imm32
	//       or
	//   lea rsp, -disp8[fp]
	//       or
	//   lea rsp, -disp32[fp]
	//

	if ((NextByteBuffer[0] == SIZE64_PREFIX) &&
		(NextByteBuffer[1] == ADD_IMM8_OP) &&
		(NextByteBuffer[2] == 0xc4)) {

		//
		// add rsp, imm8.
		//

		NextByte += 4;
		uc_mem_read(CoreBlock.uc_handle, (uint64_t)NextByte, NextByteBuffer, sizeof(NextByteBuffer));
	}
	else if ((NextByteBuffer[0] == SIZE64_PREFIX) &&
		(NextByteBuffer[1] == ADD_IMM32_OP) &&
		(NextByteBuffer[2] == 0xc4)) {

		//
		// add rsp, imm32.
		//

		NextByte += 7;
		uc_mem_read(CoreBlock.uc_handle, (uint64_t)NextByte, NextByteBuffer, sizeof(NextByteBuffer));
	}
	else if (((NextByteBuffer[0] & 0xfe) == SIZE64_PREFIX) &&
		(NextByteBuffer[1] == LEA_OP)) {

		FrameRegister = ((NextByteBuffer[0] & 0x1) << 3) | (NextByteBuffer[2] & 0x7);
		if ((FrameRegister != 0) &&
			(FrameRegister == UnwindInfoCellPtr->FrameRegister)) {

			if ((NextByteBuffer[2] & 0xf8) == 0x60) {

				//
				// lea rsp, disp8[fp].
				//

				NextByte += 4;
				uc_mem_read(CoreBlock.uc_handle, (uint64_t)NextByte, NextByteBuffer, sizeof(NextByteBuffer));
			}
			else if ((NextByteBuffer[2] & 0xf8) == 0xa0) {

				//
				// lea rsp, disp32[fp].
				//

				NextByte += 7;
				uc_mem_read(CoreBlock.uc_handle, (uint64_t)NextByte, NextByteBuffer, sizeof(NextByteBuffer));
			}
		}
	}

	//
	// Check for any number of:
	//
	//   pop nonvolatile-integer-register[0..15].
	//

	while (TRUE) {
		if ((NextByteBuffer[0] & 0xf8) == POP_OP) {
			NextByte += 1;
			uc_mem_read(CoreBlock.uc_handle, (uint64_t)NextByte, NextByteBuffer, sizeof(NextByteBuffer));
		}
		else if (IS_REX_PREFIX(NextByteBuffer[0]) &&
			((NextByteBuffer[1] & 0xf8) == POP_OP)) {

			NextByte += 2;
			uc_mem_read(CoreBlock.uc_handle, (uint64_t)NextByte, NextByteBuffer, sizeof(NextByteBuffer));
		}
		else {
			break;
		}
	}

	//
	// If the next instruction is a return or an appropriate jump, then
	// control is currently in an epilogue and execution of the epilogue
	// should be emulated. Otherwise, execution is not in an epilogue and
	// the prologue should be unwound.
	//

	InEpilogue = FALSE;
	if ((NextByteBuffer[0] == RET_OP) ||
		(NextByteBuffer[0] == RET_OP_2) ||
		((NextByteBuffer[0] == REP_PREFIX) && (NextByteBuffer[1] == RET_OP))) {

		//
		// A return is an unambiguous indication of an epilogue.
		//

		InEpilogue = TRUE;

	}
	else if ((NextByteBuffer[0] == JMP_IMM8_OP) || (NextByteBuffer[0] == JMP_IMM32_OP)) {

		//
		// An unconditional branch to a target that is equal to the start of
		// or outside of this routine is logically a call to another function.
		// 

		BranchTarget = (ULONG64)NextByte - ImageBase;
		if (NextByteBuffer[0] == JMP_IMM8_OP) {
			BranchTarget += 2 + (CHAR)NextByteBuffer[1];

		}
		else {
			BranchTarget += 5 + *((LONG UNALIGNED*) & NextByteBuffer[1]);
		}

		//
		// Determine whether the branch target refers to code within this
		// function. If not, then it is an epilogue indicator.
		//
		// A branch to the start of self implies a recursive call, so
		// is treated as an epilogue.
		//

		if (BranchTarget < FunctionEntryCell.BeginAddress ||
			BranchTarget >= FunctionEntryCell.EndAddress) {

			//
			// The branch target is outside of the region described by
			// this function entry. See whether it is contained within
			// an indirect function entry associated with this same
			// function.
			//
			// If not, then the branch target really is outside of
			// this function.
			//

			PrimaryFunctionEntry = RtlpSameFunction(FunctionEntry,
				ImageBase,
				BranchTarget + ImageBase);

			RUNTIME_FUNCTION PrimaryFunctionEntryCell;
			uc_mem_read(CoreBlock.uc_handle, (uint64_t)PrimaryFunctionEntry, &PrimaryFunctionEntryCell, sizeof(PrimaryFunctionEntryCell));

			if ((PrimaryFunctionEntry == NULL) ||
				(BranchTarget == PrimaryFunctionEntryCell.BeginAddress)) {

				InEpilogue = TRUE;
			}

		}
		else if ((BranchTarget == FunctionEntryCell.BeginAddress) &&
			((UnwindInfoCellPtr->Flags & UNW_FLAG_CHAININFO) == 0)) {

			InEpilogue = TRUE;
		}

	}
	else if ((NextByteBuffer[0] == JMP_IND_OP) && (NextByteBuffer[1] == 0x25)) {

		//
		// An unconditional jump indirect.
		//
		// This is a jmp outside of the function, probably a tail call
		// to an import function.
		//

		InEpilogue = TRUE;

	}
	else if (((NextByteBuffer[0] & 0xf8) == SIZE64_PREFIX) &&
		(NextByteBuffer[1] == 0xff) &&
		(NextByteBuffer[2] & 0x38) == 0x20) {

		//
		// This is an indirect jump opcode: 0x48 0xff /4.  The 64-bit
		// flag (REX.W) is always redundant here, so its presence is
		// overloaded to indicate a branch out of the function - a tail
		// call.
		//
		// Such an opcode is an unambiguous epilogue indication.
		//

		InEpilogue = TRUE;
	}

	if (InEpilogue != FALSE) {
		NextByte = (PUCHAR)ControlPc;
		uc_mem_read(CoreBlock.uc_handle, (uint64_t)NextByte, NextByteBuffer, sizeof(NextByteBuffer));
		//
		// Emulate one of (if any):
		//
		//   add rsp, imm8
		//       or
		//   add rsp, imm32
		//       or                
		//   lea rsp, disp8[frame-register]
		//       or
		//   lea rsp, disp32[frame-register]
		//

		if ((NextByteBuffer[0] & 0xf8) == SIZE64_PREFIX) {

			if (NextByteBuffer[1] == ADD_IMM8_OP) {

				//
				// add rsp, imm8.
				//

				ContextRecord->Rsp += (CHAR)NextByteBuffer[3];
				NextByte += 4;
				uc_mem_read(CoreBlock.uc_handle, (uint64_t)NextByte, NextByteBuffer, sizeof(NextByteBuffer));
			}
			else if (NextByteBuffer[1] == ADD_IMM32_OP) {

				//
				// add rsp, imm32.
				//

				Displacement = NextByteBuffer[3] | (NextByteBuffer[4] << 8);
				Displacement |= (NextByteBuffer[5] << 16) | (NextByteBuffer[6] << 24);
				ContextRecord->Rsp += Displacement;
				NextByte += 7;
				uc_mem_read(CoreBlock.uc_handle, (uint64_t)NextByte, NextByteBuffer, sizeof(NextByteBuffer));
			}
			else if (NextByteBuffer[1] == LEA_OP) {
				if ((NextByteBuffer[2] & 0xf8) == 0x60) {

					//
					// lea rsp, disp8[frame-register].
					//

					ContextRecord->Rsp = IntegerRegister[FrameRegister];
					ContextRecord->Rsp += (CHAR)NextByteBuffer[3];
					NextByte += 4;
					uc_mem_read(CoreBlock.uc_handle, (uint64_t)NextByte, NextByteBuffer, sizeof(NextByteBuffer));
				}
				else if ((NextByteBuffer[2] & 0xf8) == 0xa0) {

					//
					// lea rsp, disp32[frame-register].
					//

					Displacement = NextByteBuffer[3] | (NextByteBuffer[4] << 8);
					Displacement |= (NextByteBuffer[5] << 16) | (NextByteBuffer[6] << 24);
					ContextRecord->Rsp = IntegerRegister[FrameRegister];
					ContextRecord->Rsp += Displacement;
					NextByte += 7;
					uc_mem_read(CoreBlock.uc_handle, (uint64_t)NextByte, NextByteBuffer, sizeof(NextByteBuffer));
				}
			}
		}

		//
		// Emulate any number of (if any):
		//
		//   pop nonvolatile-integer-register.
		//

		while (TRUE) {
			if ((NextByteBuffer[0] & 0xf8) == POP_OP) {

				//
				// pop nonvolatile-integer-register[0..7]
				//

				RegisterNumber = NextByteBuffer[0] & 0x7;

				IntegerAddress = (PULONG64)ContextRecord->Rsp;

				uint64_t ValueFromAddress;
				uc_mem_read(CoreBlock.uc_handle, (uint64_t)IntegerAddress, &ValueFromAddress, sizeof(ValueFromAddress));

				IntegerRegister[RegisterNumber] = ValueFromAddress;
				if (ContextPointers) {
					ContextPointers->IntegerContext[RegisterNumber] = IntegerAddress;
				}

				ContextRecord->Rsp += 8;
				NextByte += 1;

			}
			else if (IS_REX_PREFIX(NextByteBuffer[0]) &&
				((NextByteBuffer[1] & 0xf8) == POP_OP)) {

				//
				// pop nonvolatile-integer-register[8..15]
				//

				RegisterNumber = ((NextByteBuffer[0] & 1) << 3) | (NextByteBuffer[1] & 0x7);

				IntegerAddress = (PULONG64)ContextRecord->Rsp;

				uc_mem_read(CoreBlock.uc_handle, (uint64_t)IntegerAddress, &ValueFromAddress, sizeof(ValueFromAddress));

				IntegerRegister[RegisterNumber] = ValueFromAddress;

				if (ContextPointers) {
					ContextPointers->IntegerContext[RegisterNumber] = IntegerAddress;
				}

				ContextRecord->Rsp += 8;
				NextByte += 2;
				uc_mem_read(CoreBlock.uc_handle, (uint64_t)NextByte, NextByteBuffer, sizeof(NextByteBuffer));
			}
			else {
				break;
			}
		}

		//
		// Emulate return and return null exception handler.
		//
		// Note: this instruction might in fact be a jmp, however
		//       we want to emulate a return regardless.
		//

		uint64_t ValueFromRsp;
		uc_mem_read(CoreBlock.uc_handle, (uint64_t)ContextRecord->Rsp, &ValueFromRsp, sizeof(ValueFromRsp));
		ContextRecord->Rip = ValueFromRsp;
		ContextRecord->Rsp += 8;
		return NULL;
	}

	//
	// Control left the specified function outside an epilogue. Unwind the
	// subject function and any chained unwind information.
	//

	FunctionEntry = RtlpUnwindPrologue(ImageBase,
		ControlPc,
		*EstablisherFrame,
		FunctionEntry,
		ContextRecord,
		ContextPointers);

	uc_mem_read(CoreBlock.uc_handle, (uint64_t)FunctionEntry, &FunctionEntryCell, sizeof(FunctionEntryCell));

	//
	// If control left the specified function outside of the prologue and
	// the function has a handler that matches the specified type, then
	// return the address of the language specific exception handler.
	// Otherwise, return NULL.
	//

	UnwindInfo = (PUNWIND_INFO)(FunctionEntryCell.UnwindData + ImageBase);

	m_cbSize = offsetof(UNWIND_INFO, UnwindCode);
	m_pBuffer = malloc(m_cbSize);

	uc_mem_read(CoreBlock.uc_handle, (uint64_t)UnwindInfo, m_pBuffer, m_cbSize);
	UnwindInfoCellPtr = (PUNWIND_INFO)m_pBuffer;

	m_cbSize = offsetof(UNWIND_INFO, UnwindCode) + UnwindInfoCellPtr->CountOfCodes * sizeof(UNWIND_CODE) + sizeof(DWORD) * 2;
	m_pBuffer = realloc(m_pBuffer, m_cbSize);

	uc_mem_read(CoreBlock.uc_handle, (uint64_t)UnwindInfo, m_pBuffer, m_cbSize);
	UnwindInfoCellPtr = (PUNWIND_INFO)m_pBuffer;

	PrologOffset = (ULONG)(ControlPc - (FunctionEntryCell.BeginAddress + ImageBase));
	if ((PrologOffset >= UnwindInfoCellPtr->SizeOfProlog) &&
		((UnwindInfoCellPtr->Flags & HandlerType) != 0)) {
		Index = UnwindInfoCellPtr->CountOfCodes;
		if ((Index & 1) != 0) {
			Index += 1;
		}

		*HandlerData = (PVOID)((PUCHAR)UnwindInfo + ((PUCHAR)&UnwindInfoCellPtr->UnwindCode[Index + 2] - (PUCHAR)UnwindInfoCellPtr));
		return (PEXCEPTION_ROUTINE)(*((PULONG)&UnwindInfoCellPtr->UnwindCode[Index]) + ImageBase);

	}
	else {
		return NULL;
	}
}

VOID UcRtlCaptureContext(
	PCONTEXT ContextRecord
)
{
	uc_reg_read(CoreBlock.uc_handle, UC_X86_REG_RIP, &ProcessBlock.ContextRecord.Rip);
	uc_reg_read(CoreBlock.uc_handle, UC_X86_REG_CS, &ProcessBlock.ContextRecord.SegCs);
	uc_reg_read(CoreBlock.uc_handle, UC_X86_REG_SS, &ProcessBlock.ContextRecord.SegSs);
	uc_reg_read(CoreBlock.uc_handle, UC_X86_REG_RSP, &ProcessBlock.ContextRecord.Rsp);
	uc_reg_read(CoreBlock.uc_handle, UC_X86_REG_EFLAGS, &ProcessBlock.ContextRecord.EFlags);

	uc_reg_read(CoreBlock.uc_handle, UC_X86_REG_DS, &ProcessBlock.ContextRecord.SegDs);
	uc_reg_read(CoreBlock.uc_handle, UC_X86_REG_ES, &ProcessBlock.ContextRecord.SegEs);
	uc_reg_read(CoreBlock.uc_handle, UC_X86_REG_FS, &ProcessBlock.ContextRecord.SegFs);
	uc_reg_read(CoreBlock.uc_handle, UC_X86_REG_GS, &ProcessBlock.ContextRecord.SegGs);

	uc_reg_read(CoreBlock.uc_handle, UC_X86_REG_RAX, &ProcessBlock.ContextRecord.Rax);
	uc_reg_read(CoreBlock.uc_handle, UC_X86_REG_RCX, &ProcessBlock.ContextRecord.Rcx);
	uc_reg_read(CoreBlock.uc_handle, UC_X86_REG_RDX, &ProcessBlock.ContextRecord.Rdx);
	uc_reg_read(CoreBlock.uc_handle, UC_X86_REG_R8, &ProcessBlock.ContextRecord.R8);
	uc_reg_read(CoreBlock.uc_handle, UC_X86_REG_R9, &ProcessBlock.ContextRecord.R9);
	uc_reg_read(CoreBlock.uc_handle, UC_X86_REG_R10, &ProcessBlock.ContextRecord.R10);
	uc_reg_read(CoreBlock.uc_handle, UC_X86_REG_R11, &ProcessBlock.ContextRecord.R11);
	uc_reg_read(CoreBlock.uc_handle, UC_X86_REG_RBP, &ProcessBlock.ContextRecord.Rbp);

	uc_reg_read(CoreBlock.uc_handle, UC_X86_REG_RBX, &ProcessBlock.ContextRecord.Rbx);
	uc_reg_read(CoreBlock.uc_handle, UC_X86_REG_RDI, &ProcessBlock.ContextRecord.Rdi);
	uc_reg_read(CoreBlock.uc_handle, UC_X86_REG_RSI, &ProcessBlock.ContextRecord.Rsi);
	uc_reg_read(CoreBlock.uc_handle, UC_X86_REG_R12, &ProcessBlock.ContextRecord.R12);
	uc_reg_read(CoreBlock.uc_handle, UC_X86_REG_R13, &ProcessBlock.ContextRecord.R13);
	uc_reg_read(CoreBlock.uc_handle, UC_X86_REG_R14, &ProcessBlock.ContextRecord.R14);
	uc_reg_read(CoreBlock.uc_handle, UC_X86_REG_R15, &ProcessBlock.ContextRecord.R15);

	uc_reg_read(CoreBlock.uc_handle, UC_X86_REG_XMM0, &ProcessBlock.ContextRecord.Xmm0);
	uc_reg_read(CoreBlock.uc_handle, UC_X86_REG_XMM1, &ProcessBlock.ContextRecord.Xmm1);
	uc_reg_read(CoreBlock.uc_handle, UC_X86_REG_XMM2, &ProcessBlock.ContextRecord.Xmm2);
	uc_reg_read(CoreBlock.uc_handle, UC_X86_REG_XMM3, &ProcessBlock.ContextRecord.Xmm3);
	uc_reg_read(CoreBlock.uc_handle, UC_X86_REG_XMM4, &ProcessBlock.ContextRecord.Xmm4);
	uc_reg_read(CoreBlock.uc_handle, UC_X86_REG_XMM5, &ProcessBlock.ContextRecord.Xmm5);

	uc_reg_read(CoreBlock.uc_handle, UC_X86_REG_XMM6, &ProcessBlock.ContextRecord.Xmm6);
	uc_reg_read(CoreBlock.uc_handle, UC_X86_REG_XMM7, &ProcessBlock.ContextRecord.Xmm7);
	uc_reg_read(CoreBlock.uc_handle, UC_X86_REG_XMM8, &ProcessBlock.ContextRecord.Xmm8);
	uc_reg_read(CoreBlock.uc_handle, UC_X86_REG_XMM9, &ProcessBlock.ContextRecord.Xmm9);
	uc_reg_read(CoreBlock.uc_handle, UC_X86_REG_XMM10, &ProcessBlock.ContextRecord.Xmm10);
	uc_reg_read(CoreBlock.uc_handle, UC_X86_REG_XMM11, &ProcessBlock.ContextRecord.Xmm11);
	uc_reg_read(CoreBlock.uc_handle, UC_X86_REG_XMM12, &ProcessBlock.ContextRecord.Xmm12);
	uc_reg_read(CoreBlock.uc_handle, UC_X86_REG_XMM13, &ProcessBlock.ContextRecord.Xmm13);
	uc_reg_read(CoreBlock.uc_handle, UC_X86_REG_XMM14, &ProcessBlock.ContextRecord.Xmm14);
	uc_reg_read(CoreBlock.uc_handle, UC_X86_REG_XMM15, &ProcessBlock.ContextRecord.Xmm15);

	uc_reg_read(CoreBlock.uc_handle, UC_X86_REG_MXCSR, &ProcessBlock.ContextRecord.MxCsr);

	uc_mem_write(CoreBlock.uc_handle, ContextRecord, &ProcessBlock.ContextRecord, sizeof(CONTEXT));
}

VOID UcRtlRestoreContext(
	IN PCONTEXT ContextRecord,
	IN PEXCEPTION_RECORD ExceptionRecord OPTIONAL
)
{
	uc_reg_write(CoreBlock.uc_handle, UC_X86_REG_CS, &ContextRecord->SegCs);
	uc_reg_write(CoreBlock.uc_handle, UC_X86_REG_DS, &ContextRecord->SegDs);
	uc_reg_write(CoreBlock.uc_handle, UC_X86_REG_ES, &ContextRecord->SegEs);
	uc_reg_write(CoreBlock.uc_handle, UC_X86_REG_SS, &ContextRecord->SegSs);
	uc_reg_write(CoreBlock.uc_handle, UC_X86_REG_FS, &ContextRecord->SegFs);
	uc_reg_write(CoreBlock.uc_handle, UC_X86_REG_GS, &ContextRecord->SegGs);

	uc_reg_write(CoreBlock.uc_handle, UC_X86_REG_RAX, &ContextRecord->Rax);
	uc_reg_write(CoreBlock.uc_handle, UC_X86_REG_RBX, &ContextRecord->Rbx);
	uc_reg_write(CoreBlock.uc_handle, UC_X86_REG_RCX, &ContextRecord->Rcx);
	uc_reg_write(CoreBlock.uc_handle, UC_X86_REG_RDX, &ContextRecord->Rdx);
	uc_reg_write(CoreBlock.uc_handle, UC_X86_REG_RSI, &ContextRecord->Rsi);
	uc_reg_write(CoreBlock.uc_handle, UC_X86_REG_RDI, &ContextRecord->Rdi);
	uc_reg_write(CoreBlock.uc_handle, UC_X86_REG_R8, &ContextRecord->R8);
	uc_reg_write(CoreBlock.uc_handle, UC_X86_REG_R9, &ContextRecord->R9);
	uc_reg_write(CoreBlock.uc_handle, UC_X86_REG_R10, &ContextRecord->R10);
	uc_reg_write(CoreBlock.uc_handle, UC_X86_REG_R11, &ContextRecord->R11);
	uc_reg_write(CoreBlock.uc_handle, UC_X86_REG_R12, &ContextRecord->R12);
	uc_reg_write(CoreBlock.uc_handle, UC_X86_REG_R13, &ContextRecord->R13);
	uc_reg_write(CoreBlock.uc_handle, UC_X86_REG_R14, &ContextRecord->R14);
	uc_reg_write(CoreBlock.uc_handle, UC_X86_REG_R15, &ContextRecord->R15);
	uc_reg_write(CoreBlock.uc_handle, UC_X86_REG_RBP, &ContextRecord->Rbp);

	uc_reg_write(CoreBlock.uc_handle, UC_X86_REG_XMM0, &ContextRecord->Xmm0);
	uc_reg_write(CoreBlock.uc_handle, UC_X86_REG_XMM1, &ContextRecord->Xmm1);
	uc_reg_write(CoreBlock.uc_handle, UC_X86_REG_XMM2, &ContextRecord->Xmm2);
	uc_reg_write(CoreBlock.uc_handle, UC_X86_REG_XMM3, &ContextRecord->Xmm3);
	uc_reg_write(CoreBlock.uc_handle, UC_X86_REG_XMM4, &ContextRecord->Xmm4);
	uc_reg_write(CoreBlock.uc_handle, UC_X86_REG_XMM5, &ContextRecord->Xmm5);
	uc_reg_write(CoreBlock.uc_handle, UC_X86_REG_XMM6, &ContextRecord->Xmm6);
	uc_reg_write(CoreBlock.uc_handle, UC_X86_REG_XMM7, &ContextRecord->Xmm7);
	uc_reg_write(CoreBlock.uc_handle, UC_X86_REG_XMM8, &ContextRecord->Xmm8);
	uc_reg_write(CoreBlock.uc_handle, UC_X86_REG_XMM9, &ContextRecord->Xmm9);
	uc_reg_write(CoreBlock.uc_handle, UC_X86_REG_XMM10, &ContextRecord->Xmm10);
	uc_reg_write(CoreBlock.uc_handle, UC_X86_REG_XMM11, &ContextRecord->Xmm11);
	uc_reg_write(CoreBlock.uc_handle, UC_X86_REG_XMM12, &ContextRecord->Xmm12);
	uc_reg_write(CoreBlock.uc_handle, UC_X86_REG_XMM13, &ContextRecord->Xmm13);
	uc_reg_write(CoreBlock.uc_handle, UC_X86_REG_XMM14, &ContextRecord->Xmm14);
	uc_reg_write(CoreBlock.uc_handle, UC_X86_REG_XMM15, &ContextRecord->Xmm15);

	uc_reg_write(CoreBlock.uc_handle, UC_X86_REG_EFLAGS, &ContextRecord->EFlags);
	uc_reg_write(CoreBlock.uc_handle, UC_X86_REG_RSP, &ContextRecord->Rsp);
	uc_reg_write(CoreBlock.uc_handle, UC_X86_REG_RIP, &ContextRecord->Rip);
	ProcessBlock.ExecuteFromRip = ContextRecord->Rip;
}


EXCEPTION_DISPOSITION RtlpExecuteHandlerForException(
	_Inout_ struct _EXCEPTION_RECORD* ExceptionRecord,
	_In_ PVOID EstablisherFrame,
	_Inout_ struct _CONTEXT* ContextRecord,
	_In_ PDISPATCHER_CONTEXT DispatcherContext
)
{
	__debugbreak();
	return ExceptionContinueExecution;
}

BOOLEAN
UcRtlDispatchException(
	IN PEXCEPTION_RECORD ExceptionRecord,
	IN PCONTEXT ContextRecord
)
{
	CONTEXT ContextRecord1;
	ULONG64 ControlPc;
	DISPATCHER_CONTEXT DispatcherContext;
	EXCEPTION_DISPOSITION Disposition;
	ULONG64 EstablisherFrame;
	ULONG ExceptionFlags;
	PEXCEPTION_ROUTINE ExceptionRoutine;
	PRUNTIME_FUNCTION FunctionEntry;
	PVOID HandlerData;
	ULONG64 HighLimit;
	PUNWIND_HISTORY_TABLE HistoryTable;
	ULONG64 ImageBase;
	ULONG64 LowLimit;
	ULONG64 NestedFrame;
	UNWIND_HISTORY_TABLE UnwindTable;
	ULONG64 ExceptionRoutineEntryCode = 0;

	UcRtlpGetStackLimits(&LowLimit, &HighLimit);
	UcRtlpCopyContext(&ContextRecord1, ContextRecord);
	ControlPc = (ULONG64)ExceptionRecord->ExceptionAddress;
	ExceptionFlags = ExceptionRecord->ExceptionFlags & EXCEPTION_NONCONTINUABLE;
	NestedFrame = 0;

	HistoryTable = &UnwindTable;
	HistoryTable->Count = 0;
	HistoryTable->Search = UNWIND_HISTORY_TABLE_NONE;
	HistoryTable->LowAddress = -1;
	HistoryTable->HighAddress = 0;

	do 
	{
		FunctionEntry = UcRtlLookupFunctionEntry(ControlPc,
			&ImageBase,
			HistoryTable);

		if (FunctionEntry != NULL) {
			ExceptionRoutine = RtlpVirtualUnwind(UNW_FLAG_EHANDLER,
				ImageBase,
				ControlPc,
				FunctionEntry,
				&ContextRecord1,
				&HandlerData,
				&EstablisherFrame,
				NULL);

			if ((EstablisherFrame < LowLimit) ||
				(EstablisherFrame > HighLimit) ||
				((EstablisherFrame & 0x7) != 0)) {

				ExceptionFlags |= EXCEPTION_STACK_INVALID;
				break;

			}
			else if (ExceptionRoutine != NULL) {
				do {
					ExceptionRecord->ExceptionFlags = ExceptionFlags;
					ExceptionFlags &= ~EXCEPTION_COLLIDED_UNWIND;
					DispatcherContext.ControlPc = ControlPc;
					DispatcherContext.ImageBase = ImageBase;
					DispatcherContext.FunctionEntry = FunctionEntry;
					DispatcherContext.EstablisherFrame = EstablisherFrame;
					DispatcherContext.ContextRecord = &ContextRecord1;
					DispatcherContext.LanguageHandler = ExceptionRoutine;
					DispatcherContext.HandlerData = HandlerData;
					DispatcherContext.HistoryTable = HistoryTable;

					uc_mem_read(CoreBlock.uc_handle, ExceptionRoutine, &ExceptionRoutineEntryCode, sizeof(ExceptionRoutineEntryCode));
					printf("ExceptionRoutineEntryCode:%llX\n", ExceptionRoutineEntryCode);

					Disposition =
						RtlpExecuteHandlerForException(ExceptionRecord,
							EstablisherFrame,
							ContextRecord,
							&DispatcherContext);

					ExceptionFlags |=
						(ExceptionRecord->ExceptionFlags & EXCEPTION_NONCONTINUABLE);

					if (NestedFrame == EstablisherFrame) {
						ExceptionFlags &= (~EXCEPTION_NESTED_CALL);
						NestedFrame = 0;
					}

					switch (Disposition) {
					case ExceptionContinueExecution:
						if ((ExceptionFlags & EXCEPTION_NONCONTINUABLE) != 0) {
							RtlRaiseStatus(STATUS_NONCONTINUABLE_EXCEPTION);

						}
						else {
							return TRUE;
						}
					case ExceptionContinueSearch:
						break;
					case ExceptionNestedException:
						ExceptionFlags |= EXCEPTION_NESTED_CALL;
						if (DispatcherContext.EstablisherFrame > NestedFrame) {
							NestedFrame = DispatcherContext.EstablisherFrame;
						}

						break;
					case ExceptionCollidedUnwind:
						ControlPc = DispatcherContext.ControlPc;
						ImageBase = DispatcherContext.ImageBase;
						FunctionEntry = DispatcherContext.FunctionEntry;
						EstablisherFrame = DispatcherContext.EstablisherFrame;
						UcRtlpCopyContext(&ContextRecord1,
							DispatcherContext.ContextRecord);

						ExceptionRoutine = DispatcherContext.LanguageHandler;
						HandlerData = DispatcherContext.HandlerData;
						HistoryTable = DispatcherContext.HistoryTable;
						ExceptionFlags |= EXCEPTION_COLLIDED_UNWIND;
						break;
					default:
                        RtlRaiseStatus(STATUS_INVALID_DISPOSITION);
					}

				} while ((ExceptionFlags & EXCEPTION_COLLIDED_UNWIND) != 0);
			}
		}
		else {
			ULONG64 RetAddr = 0;
			uc_mem_read(CoreBlock.uc_handle, ContextRecord1.Rsp, &RetAddr, sizeof(RetAddr));
			printf("RetAddr:%llX\n", RetAddr);
			if (ControlPc == RetAddr) {
				break;
			}
			ContextRecord1.Rip = RetAddr;

			ContextRecord1.Rsp += 8;
		}
        ControlPc = ContextRecord1.Rip;
	} while ((ULONG64)ContextRecord1.Rsp < HighLimit);

	ExceptionRecord->ExceptionFlags = ExceptionFlags;
	return FALSE;
}

VOID
RtlRaiseStatus(
    IN NTSTATUS Status
)
{
	CONTEXT ContextRecord;
	EXCEPTION_RECORD ExceptionRecord;

	uc_reg_read(CoreBlock.uc_handle, UC_X86_REG_RIP, &ContextRecord.Rip);
	uc_reg_read(CoreBlock.uc_handle, UC_X86_REG_CS, &ContextRecord.SegCs);
	uc_reg_read(CoreBlock.uc_handle, UC_X86_REG_SS, &ContextRecord.SegSs);
	uc_reg_read(CoreBlock.uc_handle, UC_X86_REG_RSP, &ContextRecord.Rsp);
	uc_reg_read(CoreBlock.uc_handle, UC_X86_REG_EFLAGS, &ContextRecord.EFlags);

	uc_reg_read(CoreBlock.uc_handle, UC_X86_REG_DS, &ContextRecord.SegDs);
	uc_reg_read(CoreBlock.uc_handle, UC_X86_REG_ES, &ContextRecord.SegEs);
	uc_reg_read(CoreBlock.uc_handle, UC_X86_REG_FS, &ContextRecord.SegFs);
	uc_reg_read(CoreBlock.uc_handle, UC_X86_REG_GS, &ContextRecord.SegGs);

	uc_reg_read(CoreBlock.uc_handle, UC_X86_REG_RAX, &ContextRecord.Rax);
	uc_reg_read(CoreBlock.uc_handle, UC_X86_REG_RCX, &ContextRecord.Rcx);
	uc_reg_read(CoreBlock.uc_handle, UC_X86_REG_RDX, &ContextRecord.Rdx);
	uc_reg_read(CoreBlock.uc_handle, UC_X86_REG_R8, &ContextRecord.R8);
	uc_reg_read(CoreBlock.uc_handle, UC_X86_REG_R9, &ContextRecord.R9);
	uc_reg_read(CoreBlock.uc_handle, UC_X86_REG_R10, &ContextRecord.R10);
	uc_reg_read(CoreBlock.uc_handle, UC_X86_REG_R11, &ContextRecord.R11);
	uc_reg_read(CoreBlock.uc_handle, UC_X86_REG_RBP, &ContextRecord.Rbp);

	uc_reg_read(CoreBlock.uc_handle, UC_X86_REG_RBX, &ContextRecord.Rbx);
	uc_reg_read(CoreBlock.uc_handle, UC_X86_REG_RDI, &ContextRecord.Rdi);
	uc_reg_read(CoreBlock.uc_handle, UC_X86_REG_RSI, &ContextRecord.Rsi);
	uc_reg_read(CoreBlock.uc_handle, UC_X86_REG_R12, &ContextRecord.R12);
	uc_reg_read(CoreBlock.uc_handle, UC_X86_REG_R13, &ContextRecord.R13);
	uc_reg_read(CoreBlock.uc_handle, UC_X86_REG_R14, &ContextRecord.R14);
	uc_reg_read(CoreBlock.uc_handle, UC_X86_REG_R15, &ContextRecord.R15);

	uc_reg_read(CoreBlock.uc_handle, UC_X86_REG_XMM0, &ContextRecord.Xmm0);
	uc_reg_read(CoreBlock.uc_handle, UC_X86_REG_XMM1, &ContextRecord.Xmm1);
	uc_reg_read(CoreBlock.uc_handle, UC_X86_REG_XMM2, &ContextRecord.Xmm2);
	uc_reg_read(CoreBlock.uc_handle, UC_X86_REG_XMM3, &ContextRecord.Xmm3);
	uc_reg_read(CoreBlock.uc_handle, UC_X86_REG_XMM4, &ContextRecord.Xmm4);
	uc_reg_read(CoreBlock.uc_handle, UC_X86_REG_XMM5, &ContextRecord.Xmm5);

	uc_reg_read(CoreBlock.uc_handle, UC_X86_REG_XMM6, &ContextRecord.Xmm6);
	uc_reg_read(CoreBlock.uc_handle, UC_X86_REG_XMM7, &ContextRecord.Xmm7);
	uc_reg_read(CoreBlock.uc_handle, UC_X86_REG_XMM8, &ContextRecord.Xmm8);
	uc_reg_read(CoreBlock.uc_handle, UC_X86_REG_XMM9, &ContextRecord.Xmm9);
	uc_reg_read(CoreBlock.uc_handle, UC_X86_REG_XMM10, &ContextRecord.Xmm10);
	uc_reg_read(CoreBlock.uc_handle, UC_X86_REG_XMM11, &ContextRecord.Xmm11);
	uc_reg_read(CoreBlock.uc_handle, UC_X86_REG_XMM12, &ContextRecord.Xmm12);
	uc_reg_read(CoreBlock.uc_handle, UC_X86_REG_XMM13, &ContextRecord.Xmm13);
	uc_reg_read(CoreBlock.uc_handle, UC_X86_REG_XMM14, &ContextRecord.Xmm14);
	uc_reg_read(CoreBlock.uc_handle, UC_X86_REG_XMM15, &ContextRecord.Xmm15);
	uc_reg_read(CoreBlock.uc_handle, UC_X86_REG_MXCSR, &ContextRecord.MxCsr);
	
	ExceptionRecord.ExceptionCode = Status;
	ExceptionRecord.ExceptionRecord = NULL;
	ExceptionRecord.NumberParameters = 0;
	ExceptionRecord.ExceptionFlags = EXCEPTION_NONCONTINUABLE;
	ExceptionRecord.ExceptionAddress = (PVOID)ContextRecord.Rip;
	UcRtlDispatchException(&ExceptionRecord, &ContextRecord);
}