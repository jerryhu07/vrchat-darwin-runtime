#include <windows.h>
#include <stdint.h>
#include <stdio.h>

#define PREFIX "xorl %r9d,%r9d\n\tmovq 24(%rdx),%r10\n\tmovq 24(%rdx),%r10\n\t" \
  "movl %ecx,%eax\n\taddl $17,%eax\n\t.rept 4\n\tmovq 24(%rdx),%r10\n\t.endr\n\t"
extern char readonly_fault;
__attribute__((naked,noinline,aligned(8192))) DWORD reference(DWORD value,uint64_t *data) {
  __asm__(PREFIX "pushfq\n\tpopq %rax\n\tret\n\t.fill 16384,1,0x90");
}
__attribute__((naked,noinline,aligned(8192))) void replay(DWORD value,uint64_t *data,void *denied) {
  __asm__(PREFIX ".globl readonly_fault\nreadonly_fault:\n\tmovl (%r8),%eax\n\tret\n\t.fill 16384,1,0x90");
}
static DWORD expected,seen,bad;
static LONG CALLBACK fault(EXCEPTION_POINTERS *p) {
  if(p->ExceptionRecord->ExceptionCode!=EXCEPTION_ACCESS_VIOLATION ||
     p->ContextRecord->Rip!=(uintptr_t)&readonly_fault)return EXCEPTION_CONTINUE_SEARCH;
  DWORD got=p->ContextRecord->EFlags&0xcd5;
  ++seen;bad+=got!=expected;
  printf("READONLY_FLAGS case=%lu expected=%lx got=%lx\n",seen,expected,got);
  p->ContextRecord->Rip+=3;return EXCEPTION_CONTINUE_EXECUTION;
}
int main(void) {
  setvbuf(stdout,NULL,_IONBF,0);
  void *denied=VirtualAlloc(0,16384,MEM_RESERVE|MEM_COMMIT,PAGE_NOACCESS);
  PVOID handler=AddVectoredExceptionHandler(1,fault);DWORD old;
  if(!denied||!handler||!VirtualProtect((void*)reference,1,PAGE_EXECUTE_READ,&old)||
     !VirtualProtect((void*)replay,1,PAGE_EXECUTE_READ,&old))return 2;
  MEMORY_BASIC_INFORMATION m;
  if(!VirtualQuery((void*)replay,&m,sizeof(m))||m.Protect!=PAGE_EXECUTE_READ||m.Type!=MEM_IMAGE)return 3;
  printf("READONLY_FUNCTIONS reference=%p replay=%p\n",reference,replay);
  uint64_t data[8]={0x1234,0x5678,0x9abc,0xdef0};
  for(unsigned i=0;i<512;++i){DWORD value=((i&1)?0xffffff00u:0x7fffff00u)+i;expected=reference(value,data)&0xcd5;replay(value,data,denied);}
  RemoveVectoredExceptionHandler(handler);VirtualFree(denied,0,MEM_RELEASE);
  printf("READONLY_FLAGS_RESULT seen=%lu expected=512 mismatches=%lu\n",seen,bad);
  return seen!=512?4:bad?6:0;
}
