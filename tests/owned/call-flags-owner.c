#include <windows.h>
#include <stdint.h>
#include <stdio.h>

extern char call_flags_fault, call_flags_resume;
volatile uintptr_t call_flags_expected_rsp;
static DWORD expected, seen, core_bad, stack_bad, kind;
static void *denied;

__attribute__((naked, noinline)) DWORD flag_reference(DWORD value) {
  __asm__("movl %ecx,%eax\naddl $17,%eax\npushfq\npopq %rax\nretq");
}
__attribute__((naked, noinline)) void call_flags_target(void) {
  __asm__(".globl call_flags_fault\ncall_flags_fault:\nud2\nretq");
}
__attribute__((naked, noinline)) void direct_call(DWORD value) {
  __asm__("subq $40,%rsp\nleaq -8(%rsp),%r8\n"
          "movq %r8,call_flags_expected_rsp(%rip)\n"
          "movl %ecx,%eax\naddl $17,%eax\ncallq call_flags_target\n"
          "addq $40,%rsp\nretq");
}
__attribute__((naked, noinline)) void indirect_call(DWORD value, void *target) {
  __asm__("subq $40,%rsp\nleaq -8(%rsp),%r8\n"
          "movq %r8,call_flags_expected_rsp(%rip)\n"
          "movl %ecx,%eax\naddl $17,%eax\ncallq *%rdx\n"
          ".globl call_flags_resume\ncall_flags_resume:\n"
          "addq $40,%rsp\nretq");
}

static LONG CALLBACK fault(EXCEPTION_POINTERS *p) {
  CONTEXT *c = p->ContextRecord;
  if (!kind) {
    if (p->ExceptionRecord->ExceptionCode != EXCEPTION_ILLEGAL_INSTRUCTION ||
        c->Rip != (uintptr_t)&call_flags_fault) return EXCEPTION_CONTINUE_SEARCH;
    c->Rip += 2;
  } else {
    if (p->ExceptionRecord->ExceptionCode != EXCEPTION_ACCESS_VIOLATION ||
        c->Rip != (uintptr_t)denied) return EXCEPTION_CONTINUE_SEARCH;
    c->Rip = (uintptr_t)&call_flags_resume;
  }
  DWORD got = c->EFlags & 0xcd5;
  ++seen;
  core_bad += ((got ^ expected) & 0x8c1) != 0;
  stack_bad += c->Rsp != call_flags_expected_rsp;
  printf("CALL_FLAGS kind=%lu case=%lu expected=%lx got=%lx stack_ok=%u\n",
         kind, seen, expected, got, (unsigned)(c->Rsp == call_flags_expected_rsp));
  if (kind) c->Rsp += 8; /* Skip the return address pushed before the fetch fault. */
  return EXCEPTION_CONTINUE_EXECUTION;
}

int main(void) {
  setvbuf(stdout, NULL, _IONBF, 0);
  denied = VirtualAlloc(NULL, 16384, MEM_RESERVE | MEM_COMMIT, PAGE_NOACCESS);
  PVOID handler = AddVectoredExceptionHandler(1, fault);
  if (!denied || !handler) return 2;
  for (kind = 0; kind < 2; ++kind) {
    for (unsigned i = 0; i < 512; ++i) {
      DWORD value = ((i & 1) ? 0xffffff00u : 0x7fffff00u) + i;
      expected = flag_reference(value) & 0xcd5;
      if (kind) indirect_call(value, denied);
      else direct_call(value);
    }
  }
  RemoveVectoredExceptionHandler(handler);
  VirtualFree(denied, 0, MEM_RELEASE);
  printf("CALL_FLAGS_RESULT seen=%lu expected=1024 core_bad=%lu stack_bad=%lu\n",
         seen, core_bad, stack_bad);
  /* PF/AF/DF observations are also retained for exact parent/candidate comparison. */
  return seen == 1024 && !core_bad && !stack_bad ? 0 : 1;
}
