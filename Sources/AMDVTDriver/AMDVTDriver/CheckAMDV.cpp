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
	outputString[3 * sizeof(UINT32)] = 0;
}

C_LINK UINT32 QuerySVMStatus()
{
	UINT32 result = 0;
	UINT32 cpuid_result[4] = {};
	do
	{
		//��ѯSMV֧��
		__cpuidex((int*)cpuid_result, 0x80000001, 0);

		//ecx �� 1 λ (0 base ��ͬ)
		if (!(cpuid_result[2] & 0x4))
			break;

		result |= SVM_ENABLED;

		//��ѯSVM����
		UINT64 msrValue = __readmsr(0xC0010114);

		//eax �� 4 λ
		if (msrValue & 0x10)
			break;

		result |= SVM_SUPPORTED;
	} while (false);

	return result;

}