.code

extern VmExitHandler : Proc

_mysgdt Proc
	;ִ�д洢�Ĵ�������ֻ��Ҫ10���ֽڣ����﷽��һ��
	sub rsp, 10h
	sgdt [rsp]
	;ȡlimit
	mov ax, [rsp]
	mov word ptr [rdx], ax
	;ȡbase
	mov rax, [rsp + 2]
	mov qword ptr [rcx], rax
	;��ԭջ
	add rsp, 10h
	ret
_mysgdt Endp

_mysidt Proc
;ִ�д洢�Ĵ�������ֻ��Ҫ10���ֽڣ����﷽��һ��
	sub rsp, 10h
	sidt [rsp]
	;ȡlimit
	mov ax, [rsp]
	mov word ptr [rdx], ax
	;ȡbase
	mov rax, [rsp + 2]
	mov qword ptr [rcx], rax
	;��ԭջ
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
	mov qword ptr [rcx + 170h], 0h
	
	;ȡ��ǰRflags
	pushfq
	mov rax, [rsp]
	mov [rcx + 178h], rax
	popfq

	;��ripָ���ж��Ƿ�load�Ĵ�����λ��
	mov rax, offset if_load_regs
	mov [rcx + 180h], rax

	;ȡrsp�����ֵûɶ��
	mov [rcx + 188h], rsp
	
	;ȡ��������֮��ĵ�һ����ַ
	;����ǽ������⻯֮��ִ�е�if_load_regsʱ���������Ϊload�Ĵ���֮���ִ�е�ַ
	mov rax, [rsp]
	mov [rcx + 190h], rax

	;ȡ��������֮���rsp����8����callѹ��ķ��ص�ַ
	;����ǽ������⻯֮��ִ�е�if_load_regsʱ���������Ϊ���ԭ��rsp
	mov rax, rsp
	add rax, 8h
	mov [rcx + 198h], rax

	;rax��0������load�Ĵ���
	;����ǽ������⻯֮���ٴ�ִ�е�if_load_regs
	;��Ϊrax�������ã���load�Ĵ���

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
	;rax ����ԭ
	;mov rax, [rcx + 170h]
	;��ԭrflags
	push qword ptr [rcx + 178h]
	popfq
	;��ԭrsp
	mov rsp, [rax + 198h]
	;��תָ��
	mov rax, [rax + 190h]
	jmp rax

return:
	ret
_save_or_load_regs Endp

_run_svm_vmrun Proc
;����ԭջָ��
mov rax, rsp

;�л�ջ
mov rsp, r9

;��ԭ����ջָ��ѹ���ڴ���
;��һ��push��Ϊ��rsp���뵽16
push rax
push rax

;���ݲ���
push r9
push r8
push rdx
push rcx

enter_guest:
;����guest״̬
mov rax, [rsp + 8h]
vmload rax
;����guestģʽ
vmrun rax

;����rax
push rax

;���exitcode�Ƿ��� VMEXIT_INVALID(-1) VMEXIT_BUSY(-2) VMEXIT_IDLE_REQUIRED(-3)
;����ǣ�ת��return��ţ������ŻḺ���л���ԭջָ�벢���أ�����֮��ֱ����������EnterVirtualization�е���RunVM֮��Ĵ��룩
mov rax, [rsp + 8h]
mov rax, [rax + 70h]
cmp rax, -1
je return
cmp rax, -2
je return
cmp rax, -3
je return

;����guest״̬
mov rax, [rsp + 10h]
vmsave rax

;����host״̬
mov rax, [rsp + 18h]
vmload rax

;��ԭrax
pop rax

sub rsp, 20h

;����guest�Ĵ���
;rax��VMCB���б��棬���ﲻ����
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

;����exit handler
;pVirtCpuInfo ����
mov rcx, [rsp + 1C0h]
;pGuestRegisters ����
mov rdx, rsp
;pGuestVmcbPhyAddr ����
mov r8, [rsp + 1C8h]
;pHostVmcbPhyAddr ����
mov r9, [rsp + 1D0h]

call VmExitHandler

;�ָ�guest�Ĵ���
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

;����rax
mov [rsp], rax

;�ж��Ƿ��Ѿ��˳����⻯����Ҫ��ת��guest����һ��ָ��
mov rax, [rsp - 8h]
test rax, rax
jnz exit_virtualization

;����host״̬
mov rax, [rsp + 30h]
vmsave rax

;��ԭrax
mov rax, [rsp]

add rsp, 20h

;����ȥ��ִ��vmrun�ٴν���guest
jmp enter_guest

return:
;���exitcode��ʱ��push��rax������pop���ֶ�ջƽ��
pop rax
;����ԭ����ջָ�벢����
mov rax, [rsp + 20h]
mov rsp, rax
ret

exit_virtualization:
mov [rsp + 8], rbx
add rsp, 10h
mov rax, [rsp - 18h]
sub rax, 20h
mov rbx, [rsp - 20h]
mov [rax + 18h], rbx
mov rbx, [rsp - 10h]
mov [rax + 10h], rbx
mov rbx, [rsp - 8h]
mov [rax + 8h], rbx
mov rbx, [rsp - 38h]
mov [rax], rbx
mov rsp, rax
popfq
pop rbx
pop rax
ret

_run_svm_vmrun Endp

End