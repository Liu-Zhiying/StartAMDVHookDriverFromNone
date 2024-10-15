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

_save_or_load_regs Proc	
	movaps xmmword ptr [rcx + 000h], xmm0
	movaps xmmword ptr [rcx + 010h], xmm1
	movaps xmmword ptr [rcx + 020h], xmm2
	movaps xmmword ptr [rcx + 030h], xmm3
	movaps xmmword ptr [rcx + 040h], xmm4
	movaps xmmword ptr [rcx + 050h], xmm5
	movaps xmmword ptr [rcx + 060h], xmm6
	movaps xmmword ptr [rcx + 070h], xmm7
	movaps xmmword ptr [rcx + 080h], xmm8
	movaps xmmword ptr [rcx + 090h], xmm9
	movaps xmmword ptr [rcx + 0A0h], xmm10
	movaps xmmword ptr [rcx + 0B0h], xmm11
	movaps xmmword ptr [rcx + 0C0h], xmm12
	movaps xmmword ptr [rcx + 0D0h], xmm13
	movaps xmmword ptr [rcx + 0E0h], xmm14
	movaps xmmword ptr [rcx + 0F0h], xmm15
	mov [rcx + 100h], r15
	mov [rcx + 108h], r14
	mov [rcx + 110h], r13
	mov [rcx + 118h], r12
	mov [rcx + 120h], r11
	mov [rcx + 128h], r10
	mov [rcx + 130h], r9
	mov [rcx + 138h], r8
	mov [rcx + 140h], rbp
	mov [rcx + 148h], rsi
	mov [rcx + 150h], rdi
	mov [rcx + 158h], rdx
	mov [rcx + 160h], rcx
	mov [rcx + 168h], rbx
	mov [rcx + 170h], rax
	
	;取当前Rflags
	pushfq
	mov rax, [rsp]
	mov [rcx + 178h], rax
	popfq

	;把rip指向判断是否load寄存器的位置
	mov rax, offset if_load_regs
	mov [rcx + 180h], rax
	
	;取函数返回之后的第一条地址
	;如果是进入虚拟化之后执行到if_load_regs时，这个会作为load寄存器之后的执行地址
	mov rax, [rsp]
	mov [rcx + 190h], rax

	;取函数返回之后的rsp，加8抵消call压入的返回地址
	;如果是进入虚拟化之后执行到if_load_regs时，这个会作为最后还原的rsp
	mov rax, rsp
	add rax, 8h
	mov [rcx + 188h], rax

	;rax置0，跳过load寄存器
	;如果是进入虚拟化之后再次执行到if_load_regs
	;因为rax参数设置，会load寄存器

	mov rax, 0h

if_load_regs:
	test rax, rax
	jz return

	movaps xmm0, xmmword ptr [rax + 000h]
	movaps xmm1, xmmword ptr [rax + 010h]
	movaps xmm2, xmmword ptr [rax + 020h]
	movaps xmm3, xmmword ptr [rax + 030h]
	movaps xmm4, xmmword ptr [rax + 040h]
	movaps xmm5, xmmword ptr [rax + 050h]
	movaps xmm6, xmmword ptr [rax + 060h]
	movaps xmm7, xmmword ptr [rax + 070h]
	movaps xmm8, xmmword ptr [rax + 080h]
	movaps xmm9, xmmword ptr [rax + 090h]
	movaps xmm10, xmmword ptr [rax + 0A0h]
	movaps xmm11, xmmword ptr [rax + 0B0h] 
	movaps xmm12, xmmword ptr [rax + 0C0h] 
	movaps xmm13, xmmword ptr [rax + 0D0h]
	movaps xmm14, xmmword ptr [rax + 0E0h]
	movaps xmm15, xmmword ptr [rax + 0F0h]
	mov r15, [rax + 100h]
	mov r14, [rax + 108h]
	mov r13, [rax + 110h]
	mov r12, [rax + 118h]
	mov r11, [rax + 120h]
	mov r10, [rax + 128h]
	mov r9, [rax + 130h] 
	mov r8, [rax + 138h]
	mov rbp, [rax + 140h]
	mov rsi, [rax + 148h] 
	mov rdi, [rax + 150h]
	mov rdx, [rax + 158h]
	mov rcx, [rax + 160h]
	mov rbx, [rax + 168h]
	;rax 不还原
	;mov rax, [rcx + 170h]
	;还原rflags
	push qword ptr [rcx + 178h]
	popfq
	;还原rsp
	mov rsp, [rax + 188h]
	;还原rax
	mov rax, [rax + 170h]
	jmp qword ptr [rcx + 190h]

return:
	;还原rax
	mov rax, [rcx + 170h]
	ret
_save_or_load_regs Endp

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

;备份rax
push rax

;检查exitcode是否是 VMEXIT_INVALID(-1) VMEXIT_BUSY(-2) VMEXIT_IDLE_REQUIRED(-3)
;如果是，转到return标号，这个标号会负责切换会原栈指针并返回，返回之后直接蓝屏（见EnterVirtualization中调用RunVM之后的代码）
mov rax, [rsp + 8h]
mov rax, [rax + 70h]
cmp rax, -1
je return
cmp rax, -2
je return
cmp rax, -3
je return

;保存guest状态
mov rax, [rsp + 10h]
vmsave rax

;载入host状态
mov rax, [rsp + 18h]
vmload rax

;还原rax
pop rax

sub rsp, 20h

;备份guest寄存器
;rax在VMCB中有保存，这里不保存
push 0
push 0
push 0
push 0
push 0
push 0
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
mov rcx, [rsp + 1C0h]
;pGuestRegisters 参数
mov rdx, rsp
;pGuestVmcbPhyAddr 参数
mov r8, [rsp + 1C8h]
;pHostVmcbPhyAddr 参数
mov r9, [rsp + 1D0h]

call VmExitHandler

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
add rsp, 30h

;备份rax
mov [rsp], rax

;判断是否已经退出虚拟化，需要跳转到guest的下一条指令
mov rax, [rsp - 8h]
test rax, rax
jnz exit_virtualization

;保存host状态
mov rax, [rsp + 30h]
vmsave rax

;还原rax
mov rax, [rsp]

add rsp, 20h

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
;备份rbx
mov [rsp + 8], rbx

add rsp, 10h
;获取guest的rsp指针
mov rax, [rsp - 18h]
;对guest 的 rsp 减去 20h 这里是把备份的rax rbx rflags 数据拷贝过去
;已经填写guest返回地址，方便最后切换rsp之后连续push还原寄存器并用ret返回
sub rax, 20h
;拷贝guest返回地址

mov rbx, [rsp - 20h]
mov [rax + 18h], rbx
;拷贝备份rax
mov rbx, [rsp - 10h]
mov [rax + 10h], rbx
;拷贝备份rbx
mov rbx, [rsp - 8h]
mov [rax + 8h], rbx
;拷贝人flags 
mov rbx, [rsp - 38h]
mov [rax], rbx
;切换栈指针
mov rsp, rax
;还原寄存器并跳转到guest继续执行
popfq
pop rbx
pop rax
ret

_run_svm_vmrun Endp

End