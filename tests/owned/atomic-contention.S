# SysV arguments: RDI counter/lock, ESI iterations, RDX synchronization words.
# Synchronization words: ready, start, protected counter (at byte 8).
.macro ready
  movl $1,(%rdx)
1: cmpl $0,4(%rdx)
  je 1b
.endm
.section .text.atomic32,"ax"
  ready
2: lock incl (%rdi)
  dec %esi
  jnz 2b
  xor %eax,%eax
  ret
.section .text.atomic64,"ax"
  ready
2: lock incq (%rdi)
  dec %esi
  jnz 2b
  xor %eax,%eax
  ret
.section .text.mutex,"ax"
  ready
2: xor %eax,%eax
  mov $1,%ecx
  lock cmpxchg %ecx,(%rdi)
  jne 2b
  incq 8(%rdx)
  movl $0,(%rdi)
  dec %esi
  jnz 2b
  xor %eax,%eax
  ret
