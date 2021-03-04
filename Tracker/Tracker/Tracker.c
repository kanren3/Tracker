#include "Tracker.h"

UCHAR JUMP_SELF[2] = { 0xEB,0xFE };
CORE_BLOCK CoreBlock;
PROCESS_BLOCK ProcessBlock;

BOOL
WINAPI
UcMapMemory(
	PVOID Address,
	PVOID Buffer,
	SIZE_T Size,
	ULONG Protect
)
{
	uc_err uc_error;

	uc_error = uc_mem_map(
		CoreBlock.uc_handle,
		(uint64_t)Address,
		Size,
		Protect);

	uc_error = uc_mem_write(
		CoreBlock.uc_handle,
		(uint64_t)Address,
		Buffer,
		Size);

	if (uc_error != UC_ERR_OK) {
		return FALSE;
	}

	return TRUE;
}

VOID
WINAPI
DisasmPrint(
	IN ULONG64 Address
)
{
	cs_insn insn = { 0 };
	uint8_t* code;
	size_t size;
	uint64_t address;

	UCHAR Code[0x10] = { 0 };

	uc_mem_read(CoreBlock.uc_handle, Address, Code, sizeof(Code));

	code = Code;
	size = sizeof(Code);
	address = Address;

	cs_disasm_iter(CoreBlock.cs_handle, &code, &size, &address, &insn);

	printf("address:%llX\t\t\t%s\t\t%s\n", insn.address, insn.mnemonic, insn.op_str);
}

VOID
WINAPI
HookCodeHandler(
	IN uc_engine* uc,
	IN ULONG64 address,
	IN ULONG size,
	IN PVOID user_data
)
{
	if (address < ProcessBlock.ImageBase ||
		address > ProcessBlock.ImageBase + ProcessBlock.SizeOfImage) {

		CONTEXT ThreadContext;

		uc_reg_read(CoreBlock.uc_handle, UC_X86_REG_RAX, &ThreadContext.Rax);
		uc_reg_read(CoreBlock.uc_handle, UC_X86_REG_RBX, &ThreadContext.Rbx);
		uc_reg_read(CoreBlock.uc_handle, UC_X86_REG_RCX, &ThreadContext.Rcx);
		uc_reg_read(CoreBlock.uc_handle, UC_X86_REG_RDX, &ThreadContext.Rdx);
		uc_reg_read(CoreBlock.uc_handle, UC_X86_REG_R8, &ThreadContext.R8);
		uc_reg_read(CoreBlock.uc_handle, UC_X86_REG_R9, &ThreadContext.R9);
		uc_reg_read(CoreBlock.uc_handle, UC_X86_REG_RSP, &ThreadContext.Rsp);
		uc_reg_read(CoreBlock.uc_handle, UC_X86_REG_RBP, &ThreadContext.Rbp);
		uc_reg_read(CoreBlock.uc_handle, UC_X86_REG_RIP, &ThreadContext.Rip);
		uc_reg_read(CoreBlock.uc_handle, UC_X86_REG_EFLAGS, &ThreadContext.EFlags);

		FindAndPrintSymbol("[Tracker]", address);
		DisasmPrint(address);
		getchar();
	}
}

VOID
HookSysCallHandler(
	uc_engine* uc,
	ULONG user_data
)
{
	CONTEXT ThreadContext;
	ULONG64 Parameter[11];

	if (user_data == UC_X86_INS_SYSCALL) {
		uc_reg_read(CoreBlock.uc_handle, UC_X86_REG_MXCSR, &ThreadContext.MxCsr);
		uc_reg_read(CoreBlock.uc_handle, UC_X86_REG_RAX, &ThreadContext.Rax);
		uc_reg_read(CoreBlock.uc_handle, UC_X86_REG_RBX, &ThreadContext.Rbx);
		uc_reg_read(CoreBlock.uc_handle, UC_X86_REG_RCX, &ThreadContext.Rcx);
		uc_reg_read(CoreBlock.uc_handle, UC_X86_REG_RDX, &ThreadContext.Rdx);
		uc_reg_read(CoreBlock.uc_handle, UC_X86_REG_R8, &ThreadContext.R8);
		uc_reg_read(CoreBlock.uc_handle, UC_X86_REG_R9, &ThreadContext.R9);
		uc_reg_read(CoreBlock.uc_handle, UC_X86_REG_R10, &ThreadContext.R10);
		uc_reg_read(CoreBlock.uc_handle, UC_X86_REG_R11, &ThreadContext.R11);
		uc_reg_read(CoreBlock.uc_handle, UC_X86_REG_R12, &ThreadContext.R12);
		uc_reg_read(CoreBlock.uc_handle, UC_X86_REG_R13, &ThreadContext.R13);
		uc_reg_read(CoreBlock.uc_handle, UC_X86_REG_R14, &ThreadContext.R14);
		uc_reg_read(CoreBlock.uc_handle, UC_X86_REG_R15, &ThreadContext.R15);
		uc_reg_read(CoreBlock.uc_handle, UC_X86_REG_RSI, &ThreadContext.Rsi);
		uc_reg_read(CoreBlock.uc_handle, UC_X86_REG_RDI, &ThreadContext.Rdi);
		uc_reg_read(CoreBlock.uc_handle, UC_X86_REG_RSP, &ThreadContext.Rsp);
		uc_reg_read(CoreBlock.uc_handle, UC_X86_REG_RBP, &ThreadContext.Rbp);
		uc_reg_read(CoreBlock.uc_handle, UC_X86_REG_RIP, &ThreadContext.Rip);
		uc_reg_read(CoreBlock.uc_handle, UC_X86_REG_EFLAGS, &ThreadContext.EFlags);
		uc_reg_read(CoreBlock.uc_handle, UC_X86_REG_XMM0, &ThreadContext.Xmm0);
		uc_reg_read(CoreBlock.uc_handle, UC_X86_REG_XMM1, &ThreadContext.Xmm1);
		uc_reg_read(CoreBlock.uc_handle, UC_X86_REG_XMM2, &ThreadContext.Xmm2);
		uc_reg_read(CoreBlock.uc_handle, UC_X86_REG_XMM3, &ThreadContext.Xmm3);
		uc_reg_read(CoreBlock.uc_handle, UC_X86_REG_XMM4, &ThreadContext.Xmm4);
		uc_reg_read(CoreBlock.uc_handle, UC_X86_REG_XMM5, &ThreadContext.Xmm5);
		uc_reg_read(CoreBlock.uc_handle, UC_X86_REG_XMM6, &ThreadContext.Xmm6);
		uc_reg_read(CoreBlock.uc_handle, UC_X86_REG_XMM7, &ThreadContext.Xmm7);
		uc_reg_read(CoreBlock.uc_handle, UC_X86_REG_XMM8, &ThreadContext.Xmm8);
		uc_reg_read(CoreBlock.uc_handle, UC_X86_REG_XMM9, &ThreadContext.Xmm9);
		uc_reg_read(CoreBlock.uc_handle, UC_X86_REG_XMM10, &ThreadContext.Xmm10);
		uc_reg_read(CoreBlock.uc_handle, UC_X86_REG_XMM11, &ThreadContext.Xmm11);
		uc_reg_read(CoreBlock.uc_handle, UC_X86_REG_XMM12, &ThreadContext.Xmm12);
		uc_reg_read(CoreBlock.uc_handle, UC_X86_REG_XMM13, &ThreadContext.Xmm13);
		uc_reg_read(CoreBlock.uc_handle, UC_X86_REG_XMM14, &ThreadContext.Xmm14);
		uc_reg_read(CoreBlock.uc_handle, UC_X86_REG_XMM15, &ThreadContext.Xmm15);

		uc_mem_read(CoreBlock.uc_handle, ThreadContext.Rsp, Parameter, sizeof(Parameter));
		printf("address:%llX\t\tsyscall\n", ThreadContext.Rip);
		printf("\t[+]%016llx [+]%016llx\n\t[+]%016llx [+]%016llx\n\t[+]%016llx [+]%016llx\n\t[+]%016llx [+]%016llx\n\t[+]%016llx [+]%016llx\n\t[+]%016llx\n\t[+]%016llx\n\t[+]%016llx\n\t[+]%016llx\n\t[+]%016llx\n\t[+]%016llx\n",
			ThreadContext.Rax, Parameter[0],
			ThreadContext.Rcx, Parameter[1],
			ThreadContext.Rdx, Parameter[2],
			ThreadContext.R8, Parameter[3],
			ThreadContext.R9, Parameter[4],
			Parameter[5],
			Parameter[6],
			Parameter[7],
			Parameter[8],
			Parameter[9],
			Parameter[10]);

		getchar();
	}
}

VOID HookIntrHandler(
	uc_engine* uc,
	uint32_t intno,
	void* user_data
)
{
	ULONG64 Rip = 0;
	uc_reg_read(uc, UC_X86_REG_RIP, &Rip);
	DisasmPrint(Rip);

	if (intno == 0x1)
	{
		ProcessBlock.ExceptionRecord.ExceptionCode = STATUS_SINGLE_STEP;
		ProcessBlock.ExceptionRecord.ExceptionAddress = Rip;
		ProcessBlock.ExceptionRecord.ExceptionFlags = 0;
		ProcessBlock.ExceptionRecord.ExceptionRecord = 0;
		ProcessBlock.ExceptionRecord.NumberParameters = 0;

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

		ProcessBlock.ContextRecord.EFlags &= ~0x100;
		uc_reg_write(CoreBlock.uc_handle, UC_X86_REG_EFLAGS, &ProcessBlock.ContextRecord.EFlags);
	}
	uc_emu_stop(uc);
}

BOOL
WINAPI
MapVirtualMemory(
	HANDLE ProcessHandle
)
{
	SYSTEM_INFO SystemInfo = { 0 };
	MEMORY_BASIC_INFORMATION BasicInformation = { 0 };
	SIZE_T NumberOfBytes = 0;

	PSTR Start = NULL;
	PSTR End = NULL;
	PVOID Block = NULL;

	uc_prot Protect = 0;


	GetSystemInfo(&SystemInfo);
	Start = (PSTR)SystemInfo.lpMinimumApplicationAddress;
	End = (PSTR)SystemInfo.lpMaximumApplicationAddress;

	do
	{
		NumberOfBytes = VirtualQueryEx(
			ProcessHandle,
			Start,
			&BasicInformation,
			sizeof(BasicInformation));

		if (NumberOfBytes) {

			switch (BasicInformation.Protect)
			{
			case PAGE_NOACCESS:
				Protect = UC_PROT_NONE;
				break;
			case PAGE_READONLY:
				Protect = UC_PROT_READ;
				break;
			case PAGE_READWRITE:
			case PAGE_WRITECOPY:
				Protect = UC_PROT_READ | UC_PROT_WRITE;
				break;
			case PAGE_EXECUTE:
			case PAGE_EXECUTE_READ:
				Protect = UC_PROT_READ | UC_PROT_EXEC;
				break;
			case PAGE_EXECUTE_READWRITE:
			case PAGE_EXECUTE_WRITECOPY:
				Protect = UC_PROT_ALL;
				break;
			default:
				Protect = UC_PROT_NONE;
				break;
			}

			if (Protect != UC_PROT_NONE) {

				Block = malloc(BasicInformation.RegionSize);
				ReadProcessMemory(
					ProcessHandle,
					BasicInformation.BaseAddress,
					Block,
					BasicInformation.RegionSize,
					&NumberOfBytes);

				if (Block) {

					if (UcMapMemory(
						BasicInformation.BaseAddress,
						Block,
						BasicInformation.RegionSize,
						Protect)
						) {
						printf("[ok] address:%p protect:%d\n", BasicInformation.BaseAddress, BasicInformation.Protect);
					}
					else {
						printf("[error] address:%p protect:%d\n", BasicInformation.BaseAddress, BasicInformation.Protect);
					}
				}
				free(Block);
			}

			Start += BasicInformation.RegionSize;
		}
		else {
			break;
		}
	} while (Start <= End);

	return TRUE;
}

BOOL
WINAPI
VirtualStart(
	HANDLE ProcessHandle,
	CONTEXT ThreadContext
)
{
	if (ThreadContext.Rip) {

		if (MapVirtualMemory(ProcessHandle)) {

			uc_reg_write(CoreBlock.uc_handle, UC_X86_REG_RAX, &ThreadContext.Rax);
			uc_reg_write(CoreBlock.uc_handle, UC_X86_REG_RBX, &ThreadContext.Rbx);
			uc_reg_write(CoreBlock.uc_handle, UC_X86_REG_RCX, &ThreadContext.Rcx);
			uc_reg_write(CoreBlock.uc_handle, UC_X86_REG_RDX, &ThreadContext.Rdx);
			uc_reg_write(CoreBlock.uc_handle, UC_X86_REG_R8, &ThreadContext.R8);
			uc_reg_write(CoreBlock.uc_handle, UC_X86_REG_R9, &ThreadContext.R9);
			uc_reg_write(CoreBlock.uc_handle, UC_X86_REG_R10, &ThreadContext.R10);
			uc_reg_write(CoreBlock.uc_handle, UC_X86_REG_R11, &ThreadContext.R11);
			uc_reg_write(CoreBlock.uc_handle, UC_X86_REG_R12, &ThreadContext.R12);
			uc_reg_write(CoreBlock.uc_handle, UC_X86_REG_R13, &ThreadContext.R13);
			uc_reg_write(CoreBlock.uc_handle, UC_X86_REG_R14, &ThreadContext.R14);
			uc_reg_write(CoreBlock.uc_handle, UC_X86_REG_R15, &ThreadContext.R15);
			uc_reg_write(CoreBlock.uc_handle, UC_X86_REG_RSI, &ThreadContext.Rsi);
			uc_reg_write(CoreBlock.uc_handle, UC_X86_REG_RDI, &ThreadContext.Rdi);
			uc_reg_write(CoreBlock.uc_handle, UC_X86_REG_RSP, &ThreadContext.Rsp);
			uc_reg_write(CoreBlock.uc_handle, UC_X86_REG_RBP, &ThreadContext.Rbp);

			uc_reg_write(CoreBlock.uc_handle, UC_X86_REG_EFLAGS, &ThreadContext.EFlags);

			uc_reg_write(CoreBlock.uc_handle, UC_X86_REG_XMM0, &ThreadContext.Xmm0);
			uc_reg_write(CoreBlock.uc_handle, UC_X86_REG_XMM1, &ThreadContext.Xmm1);
			uc_reg_write(CoreBlock.uc_handle, UC_X86_REG_XMM2, &ThreadContext.Xmm2);
			uc_reg_write(CoreBlock.uc_handle, UC_X86_REG_XMM3, &ThreadContext.Xmm3);
			uc_reg_write(CoreBlock.uc_handle, UC_X86_REG_XMM4, &ThreadContext.Xmm4);
			uc_reg_write(CoreBlock.uc_handle, UC_X86_REG_XMM5, &ThreadContext.Xmm5);

			uc_reg_write(CoreBlock.uc_handle, UC_X86_REG_XMM6, &ThreadContext.Xmm6);
			uc_reg_write(CoreBlock.uc_handle, UC_X86_REG_XMM7, &ThreadContext.Xmm7);
			uc_reg_write(CoreBlock.uc_handle, UC_X86_REG_XMM8, &ThreadContext.Xmm8);
			uc_reg_write(CoreBlock.uc_handle, UC_X86_REG_XMM9, &ThreadContext.Xmm9);
			uc_reg_write(CoreBlock.uc_handle, UC_X86_REG_XMM10, &ThreadContext.Xmm10);
			uc_reg_write(CoreBlock.uc_handle, UC_X86_REG_XMM11, &ThreadContext.Xmm11);
			uc_reg_write(CoreBlock.uc_handle, UC_X86_REG_XMM12, &ThreadContext.Xmm12);
			uc_reg_write(CoreBlock.uc_handle, UC_X86_REG_XMM13, &ThreadContext.Xmm13);
			uc_reg_write(CoreBlock.uc_handle, UC_X86_REG_XMM14, &ThreadContext.Xmm14);
			uc_reg_write(CoreBlock.uc_handle, UC_X86_REG_XMM15, &ThreadContext.Xmm15);
			uc_reg_write(CoreBlock.uc_handle, UC_X86_REG_MXCSR, &ThreadContext.MxCsr);

			InitGdtr(CoreBlock.uc_handle);
			InitTeb(CoreBlock.uc_handle, ProcessBlock.ThreadTeb);

			uc_mem_write(CoreBlock.uc_handle, ThreadContext.Rsp, &ProcessBlock.ExecuteEnd, sizeof(ProcessBlock.ExecuteEnd));
			uc_mem_map(CoreBlock.uc_handle, ProcessBlock.ExecuteEnd, 0x1000, UC_PROT_EXEC | UC_PROT_READ);

			uc_mem_write(
				CoreBlock.uc_handle,
				ProcessBlock.EntryPoint,
				ProcessBlock.EntryPointCode,
				sizeof(ProcessBlock.EntryPointCode));

			uc_hook_add(
				CoreBlock.uc_handle,
				&CoreBlock.uc_hook_code,
				UC_HOOK_CODE,
				HookCodeHandler,
				NULL, 1, 0);

			uc_hook_add(
				CoreBlock.uc_handle,
				&CoreBlock.uc_hook_intr,
				UC_HOOK_INTR,
				HookIntrHandler,
				NULL, 1, 0);
		
			uc_hook_add(
				CoreBlock.uc_handle,
				&CoreBlock.uc_hook_insn_syscall,
				UC_HOOK_INSN,
				HookSysCallHandler,
				UC_X86_INS_SYSCALL, 1, 0, UC_X86_INS_SYSCALL);

			ProcessBlock.ExecuteFromRip = ThreadContext.Rip;

			while (1) {
				ProcessBlock.ExceptionRecord.ExceptionCode = 0;
				CoreBlock.uc_error = uc_emu_start(CoreBlock.uc_handle, ProcessBlock.ExecuteFromRip, ProcessBlock.ExecuteEnd, 0, 0);

				if (ProcessBlock.ExceptionRecord.ExceptionCode != 0) {
					if (!UcRtlDispatchException(
						&ProcessBlock.ExceptionRecord,
						&ProcessBlock.ContextRecord)) {
						break;
					}
				}
				else{
					break;
				}
			}
			return TRUE;
		}
	}
	return FALSE;
}

BOOL
WINAPI
CreateVirtualProcess(
	PSTR FilePatch
)
{
	BOOL IsCreateProcess = FALSE;
	STARTUPINFOA StartupInfo = { 0 };
	PROCESS_INFORMATION ProcessInfo = { 0 };

	CONTEXT ThreadContext;
	
	IMAGE_DOS_HEADER DosHeader;
	IMAGE_NT_HEADERS NtHeader;

	ULONG OldProtect = 0;

	IsCreateProcess = CreateProcessA(
		NULL,
		FilePatch,
		NULL, NULL, FALSE,
		CREATE_SUSPENDED,
		NULL, NULL, 
		&StartupInfo,
		&ProcessInfo);

	if (IsCreateProcess) {	
		ThreadContext.ContextFlags = CONTEXT_ALL;
		if (GetThreadContext(ProcessInfo.hThread, &ThreadContext)) {
			
			if (ThreadContext.Rip) {
				ProcessBlock.ProcessHandle = ProcessInfo.hProcess;
				ProcessBlock.ThreadHandle = ProcessInfo.hThread;
				ProcessBlock.ThreadTeb = GetThreadTeb(ProcessInfo.hThread);

				if (ReadProcessMemory(
					ProcessInfo.hProcess,
					ThreadContext.Rdx + 0x10,
					&ProcessBlock.ImageBase,
					sizeof(ProcessBlock.ImageBase),
					NULL)) {

					ReadProcessMemory(
						ProcessInfo.hProcess,
						ProcessBlock.ImageBase,
						&DosHeader,
						sizeof(DosHeader),
						NULL);

					ReadProcessMemory(
						ProcessInfo.hProcess,
						ProcessBlock.ImageBase + DosHeader.e_lfanew,
						&NtHeader,
						sizeof(NtHeader),
						NULL);

					ProcessBlock.SizeOfImage = NtHeader.OptionalHeader.SizeOfImage;
					ProcessBlock.ExecuteEnd = ProcessBlock.ImageBase + NtHeader.OptionalHeader.SizeOfImage;
					ProcessBlock.EntryPoint = ProcessBlock.ImageBase + NtHeader.OptionalHeader.AddressOfEntryPoint;

					if (ProcessBlock.ThreadTeb && ProcessBlock.ImageBase && 
						ProcessBlock.SizeOfImage && ProcessBlock.EntryPoint) {

						ReadProcessMemory(
							ProcessInfo.hProcess,
							ProcessBlock.EntryPoint,
							&ProcessBlock.EntryPointCode,
							sizeof(ProcessBlock.EntryPointCode),
							NULL);

						VirtualProtectEx(
							ProcessInfo.hProcess,
							ProcessBlock.EntryPoint,
							sizeof(ProcessBlock.EntryPointCode),
							PAGE_EXECUTE_READWRITE,
							&OldProtect);

						WriteProcessMemory(
							ProcessInfo.hProcess,
							ProcessBlock.EntryPoint,
							JUMP_SELF,
							sizeof(JUMP_SELF),
							NULL);

						VirtualProtectEx(
							ProcessInfo.hProcess,
							ProcessBlock.EntryPoint,
							sizeof(ProcessBlock.EntryPointCode),
							OldProtect,
							&OldProtect);

						ResumeThread(ProcessInfo.hThread);

						while (true) {
							GetThreadContext(ProcessInfo.hThread, &ThreadContext);
							if (ProcessBlock.EntryPoint == ThreadContext.Rip) {
								SuspendThread(ProcessInfo.hThread);
								break;
							}
						}
						InitProcessBlock(ProcessInfo.hProcess, ProcessInfo.hThread);
						VirtualStart(ProcessInfo.hProcess, ThreadContext);
					}
				}
			}
		}
	}

	getchar();
	TerminateProcess(ProcessInfo.hProcess, 0);
	return FALSE;
}


int main()
{
	CHAR Path[MAX_PATH] = "D:/Tools/VMP3.5/VMProtect.exe";
	// D:/Tools/VMP3.5/VMProtect.exe
	// D:/Tools/Scylla_v0.9.8/Scylla_x64_en.exe
	// D:/Code/User/Project1/x64/Release/Project1.exe
	CoreBlock.uc_error = uc_open(UC_ARCH_X86, UC_MODE_64, &CoreBlock.uc_handle);
	if (CoreBlock.uc_error != UC_ERR_OK) {
		return 0;
 	}
	CoreBlock.cs_error = cs_open(CS_ARCH_X86, CS_MODE_64, &CoreBlock.cs_handle);
	if (CoreBlock.cs_error != CS_ERR_OK) {
		return 0;
	}

	ZeroMemory(&ProcessBlock, sizeof(ProcessBlock));

	CreateVirtualProcess(Path);
	uc_close(CoreBlock.uc_handle);
	cs_close(&CoreBlock.cs_handle);

	getchar();
	return 0;
}