.code
CPUString Proc
;备份参数指针
mov r10,rcx
;CPUID 输入参数
mov eax,0
mov ecx,0
cpuid
;填充结果
mov dword ptr [r10],ebx
mov dword ptr [r10 + 4],edx
mov dword ptr [r10 + 8],ecx
mov byte ptr [r10 + 12],0
;返回
ret
CPUString Endp

QuerySVMStatus Proc
;在栈中预留结果位置和备份量
sub rsp,4h
mov dword ptr [rsp],0

;查询SVM特性是否支持
mov eax,80000001H
mov ecx,0h
cpuid

;判断是否支持svm
and ecx,4h
cmp ecx,0h
jz skip_svm_support
or dword ptr [rsp],1h

;判断SVM是否就绪
mov ecx,0C0010114h
rdmsr
and eax,10h
cmp eax,0
jnz skip_svm_ready
or dword ptr [rsp],6h
jmp return

;判断SVM在BIOS里面是否启用
skip_svm_ready:
mov eax,8000000Ah
mov ecx,0h
cpuid
and edx,4h
cmp edx,0h
jz skip_svm_enable
or dword ptr [rsp],2h

skip_svm_enable:
skip_svm_support:
return:
mov eax,[rsp]
add rsp,4

ret

QuerySVMStatus Endp
End