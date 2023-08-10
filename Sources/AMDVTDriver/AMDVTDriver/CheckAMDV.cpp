#include "CheckAMDV.h"
#include <intrin.h>
#include <stdlib.h>

C_LINK void CPUString(char* outputString)
{
	UINT32 cpuid_result[4] = {};
	__cpuidex((int*)cpuid_result, 0, 0);
	memcpy(outputString, &cpuid_result[1], sizeof(UINT32));
	memcpy(outputString + sizeof(UINT32), &cpuid_result[3], sizeof(UINT32));
	memcpy(outputString + sizeof(UINT32) * 2, &cpuid_result[2], sizeof(UINT32));
}

C_LINK UINT32 QuerySVMStatus()
{
	UINT32 result = 0;
	UINT32 cpuid_result[4] = {};
	do
	{
		//查询SMV支持
		__cpuidex((int*)cpuid_result, 0x80000001, 0);

		//ecx 第 1 位 (0 base 下同)
		if (!(cpuid_result[2] & 0x4))
			break;

		result |= SVM_ENABLED;

		//查询SVM启用
		UINT64 msrValue = __readmsr(0xC0010114);

		//eax 第 4 位
		if (msrValue & 0x10)
			break;

		result |= SVM_SUPPORTED;
	} while (false);

	return result;

}
