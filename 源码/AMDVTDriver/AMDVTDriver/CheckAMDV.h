#ifndef CHECK_AMDV_H
#define CHECK_AMDV_H

#include "Basic.h"

//检查CPU类型（是否为AMD CPU）和SVM是否开启
//这个函数的实现在汇编文件CheckVTOpt.asm里面，需要传入至少13字节的缓冲区
C_LINK void CPUString(char* outputString);

//查询SVM状态，结果是SVM开头的宏标志的或组合
C_LINK UINT32 QuerySVMStatus();

//CPU支持SVM
#define SVM_SUPPORTED	0x1
//SVM已经启用
#define SVM_ENABLED		0x2
//SVM就绪（未被其他虚拟化软件占用）
#define SVM_READY		0x4


#endif
