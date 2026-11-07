#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define ADDRESS_CASE(N,D) \
__attribute__((naked,noinline)) uint64_t read_##N(uintptr_t base) { \
  __asm__("movq " #D "(%rcx),%rax; ret"); } \
__attribute__((naked,noinline)) void write_##N(uintptr_t base,uint64_t value) { \
  __asm__("movq %rdx," #D "(%rcx); ret"); } \
__attribute__((naked,noinline)) void vector_##N(uintptr_t base,void *out) { \
  __asm__("movdqu " #D "(%rcx),%xmm0; movdqu %xmm0,(%rdx); ret"); } \
__attribute__((naked,noinline)) void single_##N(uintptr_t base,void *out) { \
  __asm__("pcmpeqd %xmm0,%xmm0; movss " #D "(%rcx),%xmm0; movdqu %xmm0,(%rdx); ret"); } \
__attribute__((naked,noinline)) void double_##N(uintptr_t base,void *out) { \
  __asm__("pcmpeqd %xmm0,%xmm0; movsd " #D "(%rcx),%xmm0; movdqu %xmm0,(%rdx); ret"); }
ADDRESS_CASE(zero,0)
ADDRESS_CASE(small,24)
ADDRESS_CASE(negative,-24)
ADDRESS_CASE(simm9,255)
ADDRESS_CASE(negative_simm9,-256)
ADDRESS_CASE(limit,4095)
ADDRESS_CASE(negative_limit,-4095)
ADDRESS_CASE(large,4096)
ADDRESS_CASE(negative_large,-4096)
ADDRESS_CASE(fallback,65536)
ADDRESS_CASE(negative_fallback,-65536)

__attribute__((naked,noinline)) uint64_t scaled(uintptr_t base,uint64_t index) {
  __asm__("movq 24(%rcx,%rdx,8),%rax; ret");
}
__attribute__((naked,noinline)) void scaled_write(uintptr_t base,uint64_t index,uint64_t value) {
  __asm__("movq %r8,24(%rcx,%rdx,8); ret");
}
__attribute__((naked,noinline)) uint64_t displacement_flags(uintptr_t base) {
  __asm__("stc; movq -24(%rcx),%r8; pushfq; popq %rax; ret");
}
struct Case {
  int64_t offset;
  uint64_t (*read)(uintptr_t);
  void (*write)(uintptr_t,uint64_t);
  void (*vector)(uintptr_t,void*);
  void (*single)(uintptr_t,void*);
  void (*wide)(uintptr_t,void*);
};
#define ENTRY(N,D) {D,read_##N,write_##N,vector_##N,single_##N,double_##N}
static unsigned fault_count,fault_bad;
static uintptr_t denied_address;
extern char scalar_fault32[],scalar_resume32[],scalar_fault64[],scalar_resume64[];
__attribute__((naked,noinline)) void fault32(uintptr_t base,void *out) {
  __asm__("pcmpeqd %xmm0,%xmm0; .globl scalar_fault32; scalar_fault32: movss 24(%rcx),%xmm0; .globl scalar_resume32; scalar_resume32: movdqu %xmm0,(%rdx); ret");
}
__attribute__((naked,noinline)) void fault64(uintptr_t base,void *out) {
  __asm__("pcmpeqd %xmm0,%xmm0; .globl scalar_fault64; scalar_fault64: movsd -24(%rcx),%xmm0; .globl scalar_resume64; scalar_resume64: movdqu %xmm0,(%rdx); ret");
}
static LONG CALLBACK on_fault(EXCEPTION_POINTERS *p) {
  CONTEXT *c=p->ContextRecord;uintptr_t resume=0,expected_base=0;
  if(c->Rip==(uintptr_t)scalar_fault32){resume=(uintptr_t)scalar_resume32;expected_base=denied_address-24;}
  if(c->Rip==(uintptr_t)scalar_fault64){resume=(uintptr_t)scalar_resume64;expected_base=denied_address+24;}
  if(!resume||p->ExceptionRecord->ExceptionCode!=EXCEPTION_ACCESS_VIOLATION)return EXCEPTION_CONTINUE_SEARCH;
  ++fault_count;
  fault_bad+=p->ExceptionRecord->ExceptionInformation[0]!=0||p->ExceptionRecord->ExceptionInformation[1]!=denied_address;
  fault_bad+=c->Rcx!=expected_base||c->FltSave.XmmRegisters[0].Low!=UINT64_MAX||(uint64_t)c->FltSave.XmmRegisters[0].High!=UINT64_MAX;
  c->Rip=resume;return EXCEPTION_CONTINUE_EXECUTION;
}
int main(void) {
  setvbuf(stdout,0,_IONBF,0);
  unsigned char *allocation=VirtualAlloc(0,262144,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE);
  if(!allocation)return 2;
  unsigned checks=0,bad=0;
  const struct Case cases[]={ENTRY(zero,0),ENTRY(small,24),ENTRY(negative,-24),
    ENTRY(simm9,255),ENTRY(negative_simm9,-256),ENTRY(limit,4095),ENTRY(negative_limit,-4095),ENTRY(large,4096),
    ENTRY(negative_large,-4096),ENTRY(fallback,65536),ENTRY(negative_fallback,-65536)};
  const unsigned count=sizeof(cases)/sizeof(cases[0]);
  // First execute each site unaligned in KUSER, before ordinary memory can
  // backpatch it. Some temporary bases lie outside the shared-data page.
  const uintptr_t first_targets[]={0x7ffe00e1ULL,0x7ffe0ff9ULL};
  for(unsigned t=0;t<2;++t)for(unsigned i=0;i<count;++i) {
    uintptr_t low=first_targets[t]-(uint64_t)cases[i].offset;
    bad+=cases[i].read(low)!=cases[i].read(low+0x100000000ULL);++checks;
    uint64_t a[2],b[2];
    cases[i].single(low,a);cases[i].single(low+0x100000000ULL,b);bad+=memcmp(a,b,16)!=0;++checks;
    cases[i].wide(low,a);cases[i].wide(low+0x100000000ULL,b);bad+=memcmp(a,b,16)!=0;++checks;
  }
  for(unsigned alignment=0;alignment<16;++alignment)for(unsigned i=0;i<count;++i) {
    const uint64_t patterns[]={0,1,0x80000000ULL,0x7f800000ULL,0xff800000ULL,0x7fc01234ULL,0x7f801234ULL,
      0x8000000000000000ULL,0x7ff0000000000000ULL,0xfff0000000000000ULL,0x7ff8000012345678ULL,0x7ff0000012345678ULL};
    uint64_t input[2]={patterns[(alignment+i)%(sizeof(patterns)/sizeof(patterns[0]))],0xfedcba9876543210ULL^i},output[2]={0,0};
    unsigned char *target=allocation+131072+alignment;
    const uintptr_t base=(uintptr_t)target-(uint64_t)cases[i].offset;
    memcpy(target,input,16);
    bad+=cases[i].read(base)!=input[0];++checks;
    cases[i].vector(base,output);bad+=memcmp(output,input,16)!=0;++checks;
    uint64_t expected32[2]={(uint32_t)input[0],0},expected64[2]={input[0],0};
    cases[i].single(base,output);bad+=memcmp(output,expected32,16)!=0;++checks;
    cases[i].wide(base,output);bad+=memcmp(output,expected64,16)!=0;++checks;
    cases[i].write(base,input[1]);memcpy(output,target,8);bad+=output[0]!=input[1];++checks;
    bad+=(displacement_flags((uintptr_t)target+24)&1)!=1;++checks;
    const uintptr_t low=0x7ffe0fc0ULL+alignment-(uint64_t)cases[i].offset;
    bad+=cases[i].read(low)!=cases[i].read(low+0x100000000ULL);++checks;
  }
  const uint64_t indexes[]={0,1,UINT64_MAX,0x100000001ULL,0x7fffffffffffffffULL,0x8000000000000000ULL};
  for(unsigned i=0;i<6;++i) {
    uint64_t expected=0xaabbccdd00112233ULL+i,got=0;
    uintptr_t target=(uintptr_t)allocation+131072,base=target-indexes[i]*8-24;
    memcpy((void*)target,&expected,8);
    bad+=scaled(base,indexes[i])!=expected;++checks;
    ++expected;scaled_write(base,indexes[i],expected);memcpy(&got,(void*)target,8);
    bad+=got!=expected;++checks;
  }
  void *denied=VirtualAlloc(0,16384,MEM_RESERVE|MEM_COMMIT,PAGE_NOACCESS);
  PVOID handler=AddVectoredExceptionHandler(1,on_fault);if(!denied||!handler)return 3;
  denied_address=(uintptr_t)denied+1;uint64_t out[2]={0,0};
  fault32(denied_address-24,out);bad+=out[0]!=UINT64_MAX||out[1]!=UINT64_MAX;++checks;
  fault64(denied_address+24,out);bad+=out[0]!=UINT64_MAX||out[1]!=UINT64_MAX;++checks;
  bad+=fault_count!=2||fault_bad;++checks;
  RemoveVectoredExceptionHandler(handler);VirtualFree(denied,0,MEM_RELEASE);
  VirtualFree(allocation,0,MEM_RELEASE);
  printf("SCALAR_FPR checks=%u failures=%u\n",checks,bad);
  return bad?1:0;
}
