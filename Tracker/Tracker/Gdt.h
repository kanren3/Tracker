#ifndef _GDT_H_
#define _GDT_H_

typedef union _KGDTENTRY64 {
	struct {
		USHORT  LimitLow;
		USHORT  BaseLow;
		union {
			struct {
				UCHAR   BaseMiddle;
				UCHAR   Flags1;
				UCHAR   Flags2;
				UCHAR   BaseHigh;
			} Bytes;

			struct {
				ULONG   BaseMiddle : 8;
				ULONG   Type : 4;
				ULONG	System : 1;
				ULONG   Dpl : 2;
				ULONG   Present : 1;
				ULONG   LimitHigh : 4;
				ULONG   Avl : 1;
				ULONG   LongMode : 1;
				ULONG   DefaultBig : 1;
				ULONG   Granularity : 1;
				ULONG   BaseHigh : 8;
			} Bits;
		};

		ULONG BaseUpper;
		ULONG MustBeZero;
	};

	ULONG64 Alignment;
} KGDTENTRY64, * PKGDTENTRY64;

typedef union _SEGMENT_BASE {
	struct {
		ULONG BaseLow : 16;
		ULONG BaseMiddle : 8;
		ULONG BaseHigh : 8;
		ULONG BaseUpper : 32;
	};

	ULONG64 Base;
}SEGMENT_BASE, * PSEGMENT_BASE;

typedef union _SEGMENT_LIMIT {
	struct {
		ULONG LimitLow : 16;
		ULONG LimitHigh : 4;
	};

	ULONG Limit;
}SEGMENT_LIMIT, * PSEGMENT_LIMIT;

typedef union _SEGMENT_SELECTOR {
	struct {
		ULONG   Rpl : 2;
		ULONG   Ti : 1;
		ULONG	Index : 13;
	};

	ULONG64 Alignment;
} SEGMENT_SELECTOR, * PSEGMENT_SELECTOR;

VOID
WINAPI
InitGdtr(
	__in uc_engine* uc
);

VOID
WINAPI
InitTeb(
	__in uc_engine* uc,
	__in ULONG64 Teb
);

#endif