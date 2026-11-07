.text
.globl fli_elf_sysv_call
.seh_proc fli_elf_sysv_call
fli_elf_sysv_call:
 pushq %rdi
 .seh_pushreg %rdi
 pushq %rsi
 .seh_pushreg %rsi
 subq $168,%rsp
 .seh_stackalloc 168
 .irp n,6,7,8,9,10,11,12,13,14,15
 movdqu %xmm\n,(\n-6)*16(%rsp)
 .seh_savexmm %xmm\n,(\n-6)*16
 .endr
 .seh_endprologue
 movq %rcx,%rax
 movq %rdx,%rdi
 movq %r8,%rsi
 movq %r9,%rdx
 call *%rax
 .irp n,6,7,8,9,10,11,12,13,14,15
 movdqu (\n-6)*16(%rsp),%xmm\n
 .endr
 addq $168,%rsp
 popq %rsi
 popq %rdi
 ret
.seh_endproc
