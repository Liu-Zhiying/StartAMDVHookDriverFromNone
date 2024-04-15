#ifndef SVM_H
#define SVM_H

#include "Basic.h"

enum SVMStatus
{
	//初始值，不表示任何信息
	SVMS_UNUSED = 0x0,
	//非AMDCPU
	SVMS_NONAMDCPU = 0x1,
	//CPU支持SVM
	SVMS_SUPPORTED = 0x2,
	//SVM已经启用
	SVMS_ENABLED = 0x4,
	//SVM就绪（未被其他虚拟化软件占用）
	SVMS_READY = 0x8,
};

class SVMManager : public IManager
{
public:
	static SVMStatus CheckSVM();
	virtual NTSTATUS Init() override;
	virtual void Deinit() override;
};

#endif

