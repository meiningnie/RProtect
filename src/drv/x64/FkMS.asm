.data
extern g_ulpJmpBackPoint:QWORD;

.code
extern SuperFilter:near

SuperDetour PROC PUBLIC

	push r9;
	mov r9, rax;

	movsxd  r11,dword ptr [r10+rax*4];
	mov rax, r11;
	sar r11, 4;
	add r10, r11;

	push rax;
	push rbx;
	push rcx;
	push rdx;
	push rbp;
	push rsi;
	push rdi;
	push r8;
	push r11;
	push r12;
	push r13;
	push r14;
	push r15;

	sub rsp, 32;

	mov rcx, r9;	// ServiceId
	mov rdx, r10;	// ServiceAddr
	mov r8, r11;	// ServiceOffset
	call SuperFilter;
	mov r10, rax;

	add rsp, 32;

	pop r15;
	pop r14;
	pop r13;
	pop r12;
	pop r11;
	pop r8;
	pop rdi;
	pop rsi;
	pop rbp;
	pop rdx;
	pop rcx;
	pop rbx;
	pop rax;

	pop r9;

	cmp     edi,20h;

	push g_ulpJmpBackPoint
	ret

SuperDetour ENDP



END