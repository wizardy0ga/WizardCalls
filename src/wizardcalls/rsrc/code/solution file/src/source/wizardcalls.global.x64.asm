;Wizardcalls v2. An indirect syscall utility with hook bypassing capabilities.
;Based on:
	;https://github.com/am0nsec/HellsGate
	;https://github.com/Maldev-Academy/HellHall
	;https://github.com/trickster0/TartarusGate

.data
	pSyscall QWORD 0h				; Global variable, holds pointer to SYSCALL structure { SSN, JumpAddress ( +8 bytes ) }

.code
	; Set pSyscall global to address of SYSCALL structure pointer
	SetSyscallPointer proc
		xor eax, eax				; eax = 0
		mov pSyscall, rcx			; Move pointer argument into pSyscall variable
		ret
	SetSyscallPointer endp

	; Resolve SSN & syscall instruction address from SYSCALL structure to execute system call
	SystemCall proc
		xor r11, r11				; r11 = 0
		mov r11, pSyscall			; r11 = pSyscall
		mov r10, rcx				; r10 = function call parameters
		mov eax, [r11]				; eax = System Service Number ( SSN )
		jmp qword ptr [r11 + 8]		; Jump to syscall instruction addresss
	SystemCall endp

end
