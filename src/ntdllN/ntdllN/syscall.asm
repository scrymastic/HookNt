; syscall.asm
.code

public sys_NtCreateFile
public sys_NtWriteFile
public sys_NtReadFile

; sys_NtCreateFile
sys_NtCreateFile proc
    mov r10, rcx
    mov eax, 55h
    mov rcx, 7FFE0308h
    test byte ptr [rcx], 1
    jnz short sys_NtCreateFile_DEPRECATED

    syscall
    ret

sys_NtCreateFile_DEPRECATED:
    int 2Eh
    ret
sys_NtCreateFile endp


; sys_NtWriteFile
sys_NtWriteFile proc
    mov r10, rcx
    mov eax, 8
    mov rcx, 7FFE0308h
    test byte ptr [rcx], 1
    jnz short sys_NtWriteFile_DEPRECATED

    syscall
    ret

sys_NtWriteFile_DEPRECATED:
    int 2Eh
    ret
sys_NtWriteFile endp


; sys_NtReadFile
sys_NtReadFile proc
    mov r10, rcx
    mov eax, 6
    mov rcx, 7FFE0308h
    test byte ptr [rcx], 1
    jnz short sys_NtReadFile_DEPRECATED

    syscall
    ret

sys_NtReadFile_DEPRECATED:
    int 2Eh
    ret
sys_NtReadFile endp
end