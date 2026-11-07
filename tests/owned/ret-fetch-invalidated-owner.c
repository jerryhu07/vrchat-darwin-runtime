#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
static volatile uintptr_t expected_pc,expected_sp,expected_return;
static unsigned seen,bad;
__attribute__((naked,noinline)) void bad_return(uintptr_t target,volatile uintptr_t *sp,volatile uintptr_t *resume) {
  __asm__("movq %rsp,(%rdx)\nmovq (%rsp),%rax\nmovq %rax,(%r8)\nstc\npushq %rcx\nret");
}
__attribute__((naked,noinline)) void bad_call(uintptr_t target,volatile uintptr_t *sp,volatile uintptr_t *resume) {
  __asm__("leaq -8(%rsp),%rax; movq %rax,(%rdx); leaq 1f(%rip),%rax; movq %rax,(%r8); stc; call *%rcx; 1: ret");
}
__attribute__((naked,noinline)) void bad_jump(uintptr_t target,volatile uintptr_t *sp,volatile uintptr_t *resume) {
  __asm__("movq %rsp,(%rdx); movq (%rsp),%rax; movq %rax,(%r8); stc; jmp *%rcx");
}
static LONG CALLBACK fault(EXCEPTION_POINTERS *p) {
  if(p->ExceptionRecord->ExceptionCode!=EXCEPTION_ACCESS_VIOLATION || p->ContextRecord->Rip!=expected_pc)return EXCEPTION_CONTINUE_SEARCH;
  ++seen;bad+=p->ContextRecord->Rsp!=expected_sp || !(p->ContextRecord->EFlags&1);
  p->ContextRecord->Rip=expected_return;p->ContextRecord->Rsp=expected_sp+8;
  return EXCEPTION_CONTINUE_EXECUTION;
}
int main(void) {
  setvbuf(stdout,NULL,_IONBF,0);void *denied=VirtualAlloc(0,16384,MEM_RESERVE|MEM_COMMIT,PAGE_NOACCESS);
  PVOID h=AddVectoredExceptionHandler(1,fault);if(!denied||!h)return 2;
  // An aligned guest entry hashes to the same L1 slot as address zero.
  void *warm=VirtualAlloc((void*)0x50000000000ULL,65536,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE);DWORD old;
  if(warm!=(void*)0x50000000000ULL)return 3;
  const unsigned char body[]={0xb8,7,0,0,0,0xc3};memcpy(warm,body,sizeof(body));
  if(!VirtualProtect(warm,65536,PAGE_EXECUTE_READ,&old)||((unsigned(*)(void))warm)()!=7)return 4;
  if(!VirtualProtect(warm,65536,PAGE_READWRITE,&old))return 5;
  memcpy(warm,body,sizeof(body));
  if(!VirtualProtect(warm,65536,PAGE_EXECUTE_READ,&old))return 6;
  uintptr_t targets[]={0,1,UINT64_MAX,(uintptr_t)denied};
  void (*branches[])(uintptr_t,volatile uintptr_t*,volatile uintptr_t*)={bad_return,bad_call,bad_jump};
  for(unsigned k=0;k<3;++k)for(unsigned i=0;i<4;++i){expected_pc=targets[i];branches[k](expected_pc,&expected_sp,&expected_return);}
  RemoveVectoredExceptionHandler(h);VirtualFree(denied,0,MEM_RELEASE);VirtualFree(warm,0,MEM_RELEASE);
  printf("RET_FETCH_RESULT seen=%u expected=12 bad=%u\n",seen,bad);return seen!=12||bad;
}
