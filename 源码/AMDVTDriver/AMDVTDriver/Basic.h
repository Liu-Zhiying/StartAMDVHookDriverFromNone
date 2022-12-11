#ifndef BASIC_H
#define BASIC_H

#define WINDOWS_X64

//头文件包含，一些基础定义
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
#elif defined(WINDOWS_X86)
typedef UINT32 SIZE_TYPE;
typedef UINT32 PTR_TYPE;
#endif

#endif // !BASIC_H

