// SPDX-License-Identifier: MIT
// Actual Wine Unix-entry forwarding control; no EAC component is replaced.
.text
.globl __wine_main
.type __wine_main, @function
__wine_main:
  cmp $2, %edi
  jne launch
  movq %rdi, %r12
  movq %rsi, %r13
  movq 8(%rsi), %rsi
  leaq expected(%rip), %rdi
compare:
  movb (%rdi), %al
  cmpb (%rsi), %al
  jne launch_saved
  incq %rdi
  incq %rsi
  testb %al, %al
  jne compare
  subq $16, %rsp
  movq $0, (%rsp)
  movq %rsp, %rdi
  movl $0xf106, %eax
  syscall
  testq %rax, %rax
  jne failed
  cmpq $0, (%rsp)
  jle failed
  xorl %edi, %edi
  jmp exit_process
launch_saved:
  movq %r12, %rdi
  movq %r13, %rsi
launch:
  movq %rdi, %r12
  movq %rsi, %r13
  subq $8, %rsp
  xorl %edi, %edi
  leaq debug_name(%rip), %rsi
  call *dlsym_slot(%rip)
  testq %rax, %rax
  jz failed
  movq 8(%rax), %rdi
  movq %r12, %rsi
  movq %r13, %rdx
  movl $0xf108, %eax
  syscall
  movl $74, %edi
  jmp exit_process
failed:
  movl $73, %edi
exit_process:
  movl $231, %eax
  syscall
  ud2
.size __wine_main, .-__wine_main
expected: .asciz "--native-time-control"
debug_name: .asciz "_r_debug"
.data
.balign 8
dlsym_slot: .quad dlsym
