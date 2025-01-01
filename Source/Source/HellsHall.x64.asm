.data
	pSyscall			QWORD   0h

.code

	; Sets pSyscall to pointer to SYSTEM_CALL structure pointer
	SetSyscallPointer proc
		xor rax, rax			; rax = 0
		mov pSyscall, rcx		; move SYSTEM_CALL structure pointer to global variable
		ret
	SetSyscallPointer endp

	; Resolve SSN & syscall instruction address from SYSTEM_CALL structure,
	; execute indirect system call
	SystemCall proc
		xor r11, r11			; r11 = 0
		mov r11, pSyscall		; r11 = pSyscall
		mov r10, rcx			; move parameters to r10 register
		mov eax, [r11]			; eax = pSyscall->SSN
		jmp qword ptr [r11 + 8] ; jump to syscall address @ pSyscall->JumpAddress
		ret
	SystemCall endp

end