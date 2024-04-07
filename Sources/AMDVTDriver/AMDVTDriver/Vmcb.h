#ifndef _VMCB_H
#define _VMCB_H

#include "Basic.h"

//对应 newbluepill 的 vmcb.h 可以比较阅读

enum Opcode1InterceptBits
{
	INTR = 0x1,
	NMX = 0x2,
	SMI = 0x4,
	INIT = 0x8,
	VINITR = 0x10,
	//这个特殊 指的是 CR0 除了 bit 1 (CR0.MP) 和 bit 3 (CR0.TS) 之外的 bit 更改
	CR0_CHANGE_NOT_TSMP = 0x20,
	ReadIDTR = 0x40,
	ReadGDTR = 0x80,
	ReadLDTR = 0x100,
	ReadTR = 0x200,
	WriteIDTR = 0x400,
	WriteGDTR = 0x800,
	WriteLDTR = 0x1000,
	WriteTR = 0x2000,
	RDTSC = 0x4000,
	RDTMC = 0x8000,
	PUSHF = 0x10000,
	POPF = 0x20000,
	CPUID = 0x40000,
	RSM = 0x80000,
	IRET = 0x100000,
	INT = 0x200000,
	INVD = 0x400000,
	PAUSE = 0x800000,
	HLT = 0x1000000,
	INVLPG = 0x2000000,
	INVLPGA = 0x4000000,
	IN_OUT = 0x8000000,
	RDMSR_WRMSR = 0x10000000,
	//任务切换是触发
	TASK_SWITCH = 0x20000000,
	FERR_FREEZE = 0x40000000,
	//关闭事件触发
	SHUTDOWN_EVENT = 0x80000000,
};

enum Opcode2InterceptBits
{
	VMRUN = 0x1,
	VMCALL = 0x2,
	VMLOAD = 0x4,
	VMSAVE = 0x8,
	STGI = 0x10,
	CLGI = 0x20,
	SKINIT = 0x40,
	RDTSCP = 0x80,
	ICEBP = 0x100,
	WBINVD_WBNOINVD = 0x200,
	MONITOR_MONITORX = 0x400,
	MWAIT_MWAITX_NOT_ARMED = 0x800,
	MWAIT_MWAITX_ARMED = 0x1000,
	XSETBV = 0x2000,
	RDPRU = 0x4000,
	WriteEFER = 0x8000,
	WriteCR0 = 0x10000,
	WriteCR1 = 0x20000,
	WriteCR2 = 0x40000,
	WriteCR3 = 0x80000,
	WriteCR4 = 0x100000,
	WriteCR5 = 0x200000,
	WriteCR6 = 0x400000,
	WriteCR7 = 0x800000,
	WriteCR8 = 0x1000000,
	WriteCR9 = 0x2000000,
	WriteCR10 = 0x4000000,
	WriteCR11 = 0x8000000,
	WriteCR12 = 0x10000000,
	WriteCR13 = 0x20000000,
	WriteCR14 = 0x40000000,
	WriteCR15 = 0x80000000,
};

union VIntr
{
	UINT64 data;
	struct
	{
		UINT8 V_IPR;
		UINT8 V_IRQ : 1;
		UINT8 V_GIF : 1;
		UINT8 reservedBit : 1;
		UINT8 V_NMI : 1;
		UINT8 V_NMI_MASK : 1;
		UINT8 reservedBits1 : 3;
		UINT8 V_INTR_PRIO : 4;
		UINT8 V_IGN_TPR : 1;
		UINT8 reservedBits2 : 3;
		UINT8 V_INTR_MASKING : 1;
		UINT8 EnableGIFForGuest : 1;
		UINT8 V_NMI_ENABLE : 1;
		UINT8 ReservedBits3 : 3;
		UINT8 enableX2AVIC : 1;
		UINT8 enableAVIC : 1;
		UINT8 V_INTR_VECTOR;
		UINT8 reservedBits4[3];
	} fields;
};

union InterruptBits
{
	UINT64 data;
	struct
	{
		UINT8 INTERRUCT_SHADOW : 1;
		UINT8 GUEST_INTERRUTP_MASK : 1;
		UINT64 reservedBits : 62;
	} fields;
};

union SVMExtendFeatureBits1
{
	UINT64 data;
	struct 
	{
		UINT8 enableNestedPage : 1;
		UINT8 enableSecureEncrypted : 1;
		UINT8 enableSecureEncryptedState : 1;
		UINT8 guestModeExecuteTrap : 1;
		UINT8 enableSSSCheck : 1;
		UINT8 virtualTransparentTrap : 1;
		UINT8 enableReadonlyGuestPage : 1;
		UINT8 INVLPGB_TLBSYNC_AS_UD : 1;
		UINT8 reservedBits[7];
	} fields;
};

union AVIC_BAR
{
	UINT64 data;
	struct 
	{
		UINT64 APIC_BAR : 52;
		UINT64 reservedBits : 12;
	} fields;
};

union EventInj
{
	UINT64 data;
	struct
	{
		UINT8 vector : 8;
		UINT8 type : 3;
		UINT8 ev : 1;
		UINT8 resvd1 : 19;
		UINT8 v : 1;
		UINT64 errorcode : 32;
	} fields;
};

struct SVMExtendFeatureBits2
{
	UINT64 data;
	struct
	{
		UINT8 enableLBRVirtualcation : 1;
		UINT8 enableVirtualized_VMSAVE_VMLOAD : 1;
		UINT8 reservedBits : 62;
	} fields;
};

struct VMCBCleanBits
{
	UINT32 bits;
	UINT32 reservedBits;
};

struct VMCB
{
	//CRX读中断
	UINT16 interceptReadCRX;
	//CRX写中断
	UINT16 intreceptWriteCRX;
	//DRX读中断
	UINT16 interceptReadDRX;
	//DRX写中断
	UINT16 intreceptWriteDRX;
	//异常中断
	UINT32 interceptExceptionX;
	//特殊指令的中断
	UINT32 interceptOpcodes1;
	UINT32 interceptOpcodes2;
	//保留不使用
	UINT8 reserved1[0x24];
	UINT16 pauseFilterTheshold;
	UINT16 pauseFilterCount;
	UINT64 iopmBasePA;
	UINT64 msrpmBasePA;
	UINT64 tscOffset;
	UINT32 guestASID;
	UINT8 tlbControl;
	UINT8 reserved2[3];
	VIntr vintr;
	InterruptBits interruptBIts;
	UINT64 exitCode;
	UINT64 exitInfo1;
	UINT64 exitInfo2;
	UINT64 exitIntInfo;
	SVMExtendFeatureBits1 extendFeatures1;
	AVIC_BAR avic;
	UINT64 physicalAddressGHCB;
	EventInj eventInj;
	UINT64 n_Cr3;
	SVMExtendFeatureBits2 extendFeatures2;
	VMCBCleanBits cleanBits;
	UINT64 n_Rip;
};

#endif
