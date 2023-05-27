#ifndef BASIC_H
#define BASIC_H

#define WINDOWS_X64

//头文件包含，一些基础定义
#include <ntddk.h>
#include <wdm.h>

//在C++编译器下使用C链接
#ifdef __cplusplus
#define C_LINK extern "C"
#else
#define C_LINK
#endif // __cplusplus

typedef unsigned char UINT8;
typedef char SINT8;
typedef unsigned short UINT16;
typedef short SINT16;
typedef unsigned int UINT32;
typedef int SINT32;
typedef unsigned long long UINT64;
typedef long long SINT64;

//为了将来移植到32位Windows做准备
//现在只支持64位

#if defined(WINDOWS_X64)
typedef UINT64 SIZE_TYPE;
typedef UINT64 PTR_TYPE;
const PTR_TYPE PTR_VAL_MAX = 0xffffffffffffffff;
#elif defined(WINDOWS_X86)
typedef UINT32 SIZE_TYPE;
typedef UINT32 PTR_TYPE;
const PTR_TYPE PTR_VAL_MAX = 0xffffffff;
#endif

//Windows 10 2004前后操作内存的函数有不同
#define ExAllocateMem ExAllocatePool2
#define ExFreeMem ExFreePoolWithTag

//设置tag
#define C_TO_U32(c) ((UINT32)(c))
#define MAKE_TAG(c1,c2,c3,c4) (UINT32)((C_TO_U32(c4) << 24) + (C_TO_U32(c3) << 16) + (C_TO_U32(c2) << 8) + C_TO_U32(c1))

#endif // !BASIC_H

