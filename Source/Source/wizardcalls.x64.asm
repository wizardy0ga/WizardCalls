.code

	; Set non-volatile register to address of SYSCALL structure pointer

	SetSyscallPointer proc
		xor r15, r15			; r15 = 0
		mov r15, rcx			; move to SYSCALL structure to non-volatile register
		ret
	SetSyscallPointer endp

	; Resolve SSN & syscall instruction address from SYSCALL structure to execute system call

	SystemCall proc
		mov r10, rcx			; move parameters to r10 register
		mov eax, [r15]			; eax = pSyscall->SSN
		jmp qword ptr [r15 + 8]	; jump to syscall address @ pSyscall->JumpAddress
		xor r15, r15
		ret
	SystemCall endp

end