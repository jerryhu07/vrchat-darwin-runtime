#include <windows.h>
#include <stdint.h>
#include <stdio.h>
extern char stack_fault_one,stack_fault_two,leave_fault;
static unsigned seen,bad;
static LONG CALLBACK fault(EXCEPTION_POINTERS *p) {
  if(p->ExceptionRecord->ExceptionCode!=EXCEPTION_ACCESS_VIOLATION)return EXCEPTION_CONTINUE_SEARCH;
  CONTEXT *c=p->ContextRecord;
  int leave=c->Rip==(uintptr_t)&leave_fault;
  if(!leave&&c->Rip!=(uintptr_t)&stack_fault_one&&c->Rip!=(uintptr_t)&stack_fault_two)return EXCEPTION_CONTINUE_SEARCH;
  ++seen;bad+=c->Rsp!=c->R10-(leave?0:96)||c->R9!=0x1122334455667788ULL;
  c->Rip+=leave?1:3;return EXCEPTION_CONTINUE_EXECUTION;
}
__attribute__((naked,noinline)) void stack_changes(void *denied,uint64_t *data) {
  __asm__("movq %rsp,%r10\n\tlea -64(%rsp),%rsp\n\tmovq (%rdx),%r9\n\t"
          "lea -32(%rsp),%rsp\n\t.globl stack_fault_one\nstack_fault_one:\n\tmovq (%rcx),%rax\n\t"
          "movq (%rdx),%r9\n\t.globl stack_fault_two\nstack_fault_two:\n\tmovq (%rcx),%rax\n\t"
          "lea 96(%rsp),%rsp\n\tret");
}
__attribute__((naked,noinline)) void leave_changes(void *denied,uint64_t *data) {
  __asm__("pushq %rbp\n\tmovq %rsp,%r10\n\tmovq %rcx,%rbp\n\tmovq (%rdx),%r9\n\t"
          ".globl leave_fault\nleave_fault:\n\tleave\n\tmovq %r10,%rsp\n\tpopq %rbp\n\tret");
}
int main(void) {
  setvbuf(stdout,NULL,_IONBF,0);
  void *denied=VirtualAlloc(0,16384,MEM_RESERVE|MEM_COMMIT,PAGE_NOACCESS);
  PVOID handler=AddVectoredExceptionHandler(1,fault);if(!denied||!handler)return 2;
  uint64_t data=0x1122334455667788ULL;
  for(unsigned i=0;i<50;++i){stack_changes(denied,&data);leave_changes(denied,&data);}
  RemoveVectoredExceptionHandler(handler);VirtualFree(denied,0,MEM_RELEASE);
  printf("RSP_CHECKPOINT seen=%u expected=150 bad=%u\n",seen,bad);
  return seen==150&&!bad?0:1;
}
