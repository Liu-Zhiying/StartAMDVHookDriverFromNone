.code

extern VmExitHandler : Proc

_mysgdt Proc
	;执行存储寄存器数据只需要10个字节，这里方便一点
	sub rsp, 10h
	sgdt [rsp]
	;取limit
	mov ax, [rsp]
	mov word ptr [rdx], ax
	;取base
	mov rax, [rsp + 2]
	mov qword ptr [rcx], rax
	;还原栈
	add rsp, 10h
	ret
_mysgdt Endp

_mysidt Proc
;执行存储寄存器数据只需要10个字节，这里方便一点
	sub rsp, 10h
	sidt [rsp]
	;取limit
	mov ax, [rsp]
	mov word ptr [rdx], ax
	;取base
	mov rax, [rsp + 2]
	mov qword ptr [rcx], rax
	;还原栈
	add rsp, 10h
	ret
_mysidt Endp
	
_mysldt Proc
	sldt ax
	mov word ptr [rcx], ax
	ret
_mysldt Endp

_mystr Proc
	str ax
	mov word ptr [rcx], ax
	ret
_mystr Endp

_cs_selector Proc
	mov ax,cs;
	ret
_cs_selector Endp

_ds_selector Proc
	mov ax,ds
	ret
_ds_selector Endp

_es_selector Proc
	mov ax,es
	ret
_es_selector Endp

_fs_selector Proc
	mov ax,fs
	ret
_fs_selector Endp

_gs_selector Proc
	mov ax,gs
	ret
_gs_selector Endp

_ss_selector Proc
	mov ax,ss
	ret
_ss_selector Endp

_save_rip_rsp_rflags Proc
	;取函数返回之后的第一条地址
	mov rax, [rsp]
	mov [rcx], rax
	;取函数返回之后的rsp，加8抵消call压入的返回地址
	mov rax, rsp
	add rax, 8h
	mov [rdx], rax
	;取当前Rflags
	pushfq
	mov rax, [rsp]
	mov [r8], rax
	popfq

	ret
_save_rip_rsp_rflags Endp

_run_svm_vmrun Proc
;备份原栈指针
mov rax, rsp
;切换栈
mov rsp, r9
;把原来的栈指针压到内存中
;多一个push是为了rsp对齐到16
push rax
push rax
;备份参数
push r9
push r8
push rdx
push rcx

enter_guest:
;载入guest状态
mov rax, [rsp + 8h]
vmload rax
;进入guest模式
vmrun rax
;检查exitcode是否是 VMEXIT_INVALID(-1) VMEXIT_BUSY(-2) VMEXIT_IDLE_REQUIRED(-3)
;如果是，转到return标号，这个标号会负责切换会原栈指针并返回，返回之后直接蓝屏（见EnterVirtualization中调用RunVM之后的代码）
push rax
mov rax, [rsp + 8h]
mov rax, [rax + 70h]
cmp rax, -1
je return
cmp rax, -2
je return
cmp rax, -3
je return
pop rax
;保存guest状态
push rax
mov rax, [rsp + 10h]
vmsave rax
pop rax
;载入host状态
push rax
mov rax, [rsp + 18h]
vmload rax
pop rax
;预留空间保存#VMEXIT处理函数的返回值，并且保持对齐到16字节
sub rsp, 10h
mov qword ptr [rsp], 0h;
mov qword ptr [rsp + 8h], 0h;
;备份guest寄存器
;rax在VMCB中有保存，这里不保存
push rbx
push rcx
push rdx
push rdi
push rsi
push rbp
push r8
push r9
push r10
push r11
push r12
push r13
push r14
push r15
sub rsp, 100h
movaps xmmword ptr [rsp + 000h], xmm0
movaps xmmword ptr [rsp + 010h], xmm1
movaps xmmword ptr [rsp + 020h], xmm2
movaps xmmword ptr [rsp + 030h], xmm3
movaps xmmword ptr [rsp + 040h], xmm4
movaps xmmword ptr [rsp + 050h], xmm5
movaps xmmword ptr [rsp + 060h], xmm6
movaps xmmword ptr [rsp + 070h], xmm7
movaps xmmword ptr [rsp + 080h], xmm8
movaps xmmword ptr [rsp + 090h], xmm9
movaps xmmword ptr [rsp + 0A0h], xmm10
movaps xmmword ptr [rsp + 0B0h], xmm11
movaps xmmword ptr [rsp + 0C0h], xmm12
movaps xmmword ptr [rsp + 0D0h], xmm13
movaps xmmword ptr [rsp + 0E0h], xmm14
movaps xmmword ptr [rsp + 0F0h], xmm15

;调用exit handler
;pVirtCpuInfo 参数
mov rcx, [rsp + 180h]
;pGuestRegisters 参数
mov rdx, rsp
;pGuestVmcbPhyAddr 参数
mov r8, [rsp + 188h]
;pHostVmcbPhyAddr 参数
mov r9, [rsp + 190h]

call VmExitHandler
;保留#VMEXIT函数的返回值
mov [rsp + 178h], rax

;恢复guest寄存器
movaps xmm0, xmmword ptr [rsp + 000h]
movaps xmm1, xmmword ptr [rsp + 010h]
movaps xmm2, xmmword ptr [rsp + 020h]
movaps xmm3, xmmword ptr [rsp + 030h]
movaps xmm4, xmmword ptr [rsp + 040h]
movaps xmm5, xmmword ptr [rsp + 050h]
movaps xmm6, xmmword ptr [rsp + 060h]
movaps xmm7, xmmword ptr [rsp + 070h]
movaps xmm8, xmmword ptr [rsp + 080h]
movaps xmm9, xmmword ptr [rsp + 090h]
movaps xmm10, xmmword ptr [rsp + 0A0h]
movaps xmm11, xmmword ptr [rsp + 0B0h]
movaps xmm12, xmmword ptr [rsp + 0C0h]
movaps xmm13, xmmword ptr [rsp + 0D0h]
movaps xmm14, xmmword ptr [rsp + 0E0h]
movaps xmm15, xmmword ptr [rsp + 0F0h]
add rsp, 100h
pop r15
pop r14
pop r13
pop r12
pop r11
pop r10
pop r9
pop r8
pop rbp
pop rsi
pop rdi
pop rdx
pop rcx
pop rbx

;判断是否已经退出虚拟化，需要跳转到guest的下一条指令
mov rax, [rsp + 8h]
add rsp, 10h
test rax, rax
jnz exit_virtualization

push rax
mov rax, [rsp + 18h]
vmsave rax
pop rax

;调回去，执行vmrun再次进入guest
jmp enter_guest

return:
;检查exitcode的时候push了rax，这里pop保持堆栈平衡
pop rax
;载入原来的栈指针并返回
mov rax, [rsp + 20h]
mov rsp, rax
ret

exit_virtualization:
mov rsp, rbx
jmp rax

_run_svm_vmrun Endp

End