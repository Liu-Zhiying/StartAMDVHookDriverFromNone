.code

;rcx 要调用的函数
;rdx 函数的参数
;r8 DelayProcessInGuestFromVMM对象的指针

DelayProcessEntryInGuest Proc
;调整堆栈，适应SSE XMM对齐
push rax
;调用处理函数
mov rax, rcx
sub rsp, 28h
mov rcx, rdx
mov rdx, r8
call rax
add rsp, 28h
;调用 DelayProcessInGuestFromVMM::CpuidHandler::HandleCpuid 这个函数会还原倒原来的guest状态执行
mov rax, 400000FFh
mov rcx, r8
cpuid

DelayProcessEntryInGuest Endp

End