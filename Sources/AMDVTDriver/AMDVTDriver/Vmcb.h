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
	RDTMC = 0x8000
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
};

#endif
