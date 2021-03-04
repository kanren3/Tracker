#include "Tracker.h"

VOID
WINAPI
InitDescriptor(
	__in PKGDTENTRY64 GdtEntry,
	__in ULONG64 Base,
	__in ULONG Limit,
	__in BOOLEAN Code
)
{
	SEGMENT_BASE SegmentBase = { 0 };
	SEGMENT_LIMIT SegmentLimit = { 0 };

	SegmentBase.Base = Base;
	SegmentLimit.Limit = Limit;

	GdtEntry->Alignment = 0;

	GdtEntry->BaseLow = (USHORT)SegmentBase.BaseLow;
	GdtEntry->Bits.BaseMiddle = SegmentBase.BaseMiddle;
	GdtEntry->Bits.BaseHigh = SegmentBase.BaseHigh;
	GdtEntry->BaseUpper = SegmentBase.BaseUpper;

	if (Limit > 0xFFFFF) {
		GdtEntry->Bits.Granularity = 1;
		SegmentLimit.Limit >>= 12;
	}
	GdtEntry->LimitLow = (USHORT)SegmentLimit.LimitLow;
	GdtEntry->Bits.LimitHigh = SegmentLimit.LimitHigh;

	GdtEntry->Bits.Dpl = 3;
	GdtEntry->Bits.Present = 1;
	GdtEntry->Bits.DefaultBig = 1;
	GdtEntry->Bits.System = 1;
	GdtEntry->Bits.LongMode = 1;
	GdtEntry->Bits.Type = Code ? 11 : 3;
}

VOID
WINAPI
InitGdtr(
	__in uc_engine* uc
)
{
	KGDTENTRY64 Gdt[8] = { 0 };
	SEGMENT_SELECTOR Selector = { 0 };

	InitDescriptor(&Gdt[0], 0, 0xFFFFFFFF, TRUE);
	InitDescriptor(&Gdt[1], 0, 0xFFFFFFFF, FALSE);

	Selector.Rpl = 3;
	Selector.Ti = 0;

	Selector.Index = 0;
	uc_reg_write(uc, UC_X86_REG_CS, &Selector.Alignment);

	Selector.Index = 1;
	uc_reg_write(uc, UC_X86_REG_DS, &Selector.Alignment);
	uc_reg_write(uc, UC_X86_REG_SS, &Selector.Alignment);
	uc_reg_write(uc, UC_X86_REG_GS, &Selector.Alignment);
	uc_reg_write(uc, UC_X86_REG_ES, &Selector.Alignment);
	uc_reg_write(uc, UC_X86_REG_FS, &Selector.Alignment);

	uc_x86_mmr Gdtr = { 0 };
	Gdtr.base = 0xFFFFF00000000000;
	Gdtr.limit = sizeof(Gdt) - 1;

	uc_mem_map(uc, Gdtr.base, 0x1000, UC_PROT_READ);
	uc_mem_write(uc, Gdtr.base, Gdt, sizeof(Gdt));
	uc_reg_write(uc, UC_X86_REG_GDTR, &Gdtr);
}

VOID
WINAPI
InitTeb(
	__in uc_engine* uc,
	__in ULONG64 Teb
)
{
	uc_x86_msr msr;
	msr.rid = 0xC0000101;
	msr.value = Teb;

	uc_reg_write(uc, UC_X86_REG_MSR, &msr);
}