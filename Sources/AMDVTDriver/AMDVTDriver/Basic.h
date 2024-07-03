#ifndef BASIC_H
#define BASIC_H

//表明是64位Windows，目前仅开发64位版本
#define WINDOWS_X64
//控制内存分配函数的使用
//具体见https://learn.microsoft.com/zh-cn/windows-hardware/drivers/ddi/wdm/nf-wdm-exallocatepoolwithtag
#define _BUILD_WIN_2004

//头文件包含，一些基础定义
#include <ntddk.h>

//一些类型别名
typedef unsigned char UINT8;
typedef char SINT8;
typedef unsigned short UINT16;
typedef short SINT16;
typedef unsigned int UINT32;
typedef int SINT32;
typedef unsigned long long UINT64;
typedef long long SINT64;
#if defined(WINDOWS_X64)
typedef UINT64 SIZE_TYPE;
typedef UINT64 PTR_TYPE;
#elif defined(WINDOWS_X86)
typedef UINT32 SIZE_TYPE;
typedef UINT32 PTR_TYPE;
#endif

//设置tag
#define C_TO_U32(c) ((UINT32)(c))
#define MAKE_TAG(c1,c2,c3,c4) (UINT32)((C_TO_U32(c4) << 24) + (C_TO_U32(c3) << 16) + (C_TO_U32(c2) << 8) + C_TO_U32(c1))

//全局placement new 和 placement delete
void* operator new(size_t, void* pObj);
void operator delete(void*, UINT64);

//调用placement new
template<typename T>
void CallConstructor(T* pObj)
{
	new (pObj) T;
}

//调用placement delete
template<typename T>
void CallDestroyer(T* pObj)
{
	delete (0, pObj);
}

//对于驱动各个组件的一个抽象
class IManager
{
public:
	virtual NTSTATUS Init() = 0;
	virtual void Deinit() = 0;
	virtual ~IManager() {}
};

//帮助函数，取数组的元素数目
template<typename T, SIZE_T n>
SIZE_T GetArrayElementCnt(T (&)[n])
{
	return n;
}

const PHYSICAL_ADDRESS highestPhyAddr = { (ULONG)-1,-1 };

const UINT32 IA32_MSR_EFER = 0xc0000080;
const UINT32 IA32_MSR_PAT = 0x00000277;
const UINT32 IA32_MSR_FS_BASE = 0xC0000100;
const UINT32 IA32_MSR_GS_BASE = 0xC0000101;
const UINT32 IA32_MSR_KERNEL_GS_BASE = 0xC0000102;
const UINT32 IA32_MSR_STAR = 0xC0000081;
const UINT32 IA32_MSR_LSTAR = 0xC0000082;
const UINT32 IA32_MSR_CSTAR = 0xC0000083;
const UINT32 IA32_MSR_SF_MASK = 0xC0000084;
const UINT32 IA32_MSR_SYSENTER_CS = 0x174;
const UINT32 IA32_MSR_SYSENTER_ESP = 0x175;
const UINT32 IA32_MSR_SYSENTER_EIP = 0x176;
const UINT32 IA32_MSR_SVM_MSR_VM_HSAVE_PA = 0xC0010117;
const UINT32 IA32_MSR_VM_CR = 0xC0010114;
const UINT32 EFER_SVME_OFFSET = 12;
const UINT32 CPUID_FN_80000001_ECX_SVM_OFFSET = 2;
const UINT32 VM_CR_SVMDIS_OFFSET = 4;
const UINT32 CPUID_FN_SVM_FEATURE = 0x80000001;

#endif // !BASIC_H

