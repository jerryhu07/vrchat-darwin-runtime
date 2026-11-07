#include <windows.h>
#include <stdint.h>
#include <stdio.h>
extern char control_ud2,control_resume;
__attribute__((naked,noinline,aligned(8192))) DWORD reference(DWORD value) {
  __asm__("movl %ecx,%eax\n\taddl $17,%eax\n\tpushfq\n\tpopq %rax\n\tret\n\t.fill 16384,1,0x90");
}
__attribute__((naked,noinline,aligned(8192))) void trap(DWORD value) {
  __asm__("movl %ecx,%eax\n\taddl $17,%eax\n\t.globl control_ud2\ncontrol_ud2:\n\tud2\n\tret\n\t.fill 16384,1,0x90");
}
__attribute__((naked,noinline,aligned(8192))) void branch(DWORD value,void *target) {
  __asm__("movl %ecx,%eax\n\taddl $17,%eax\n\tjnc 1f\n\tjmpq *%rdx\n1:\n\tjmpq *%rdx\n\t"
          ".globl control_resume\ncontrol_resume:\n\tret\n\t.fill 16384,1,0x90");
}
static DWORD expected,seen,bad,kind;
static void *denied;
static LONG CALLBACK fault(EXCEPTION_POINTERS *p) {
  CONTEXT *c=p->ContextRecord;
  if(!kind) {
    if(p->ExceptionRecord->ExceptionCode!=EXCEPTION_ILLEGAL_INSTRUCTION||c->Rip!=(uintptr_t)&control_ud2)return EXCEPTION_CONTINUE_SEARCH;
    c->Rip+=2;
  } else {
    if(p->ExceptionRecord->ExceptionCode!=EXCEPTION_ACCESS_VIOLATION||c->Rip!=(uintptr_t)denied)return EXCEPTION_CONTINUE_SEARCH;
    c->Rip=(uintptr_t)&control_resume;
  }
  ++seen;DWORD got=c->EFlags&0xcd5;bad+=got!=expected;
  printf("CONTROL_FLAGS kind=%lu case=%lu expected=%lx got=%lx\n",kind,seen,expected,got);
  return EXCEPTION_CONTINUE_EXECUTION;
}
int main(void) {
  setvbuf(stdout,NULL,_IONBF,0);DWORD old;
  denied=VirtualAlloc(0,16384,MEM_RESERVE|MEM_COMMIT,PAGE_NOACCESS);
  PVOID handler=AddVectoredExceptionHandler(1,fault);if(!denied||!handler)return 2;
  void *code[]={(void*)reference,(void*)trap,(void*)branch};
  for(unsigned i=0;i<3;++i)if(!VirtualProtect(code[i],1,PAGE_EXECUTE_READ,&old))return 3;
  for(kind=0;kind<2;++kind)for(unsigned i=0;i<512;++i) {
    DWORD value=((i&1)?0xffffff00u:0x7fffff00u)+i;expected=reference(value)&0xcd5;
    if(kind)branch(value,denied);else trap(value);
  }
  RemoveVectoredExceptionHandler(handler);VirtualFree(denied,0,MEM_RELEASE);
  printf("CONTROL_FLAGS_RESULT seen=%lu expected=1024 mismatches=%lu\n",seen,bad);
  return seen!=1024?4:bad?6:0;
}
