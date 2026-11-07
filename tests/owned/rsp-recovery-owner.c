#include <windows.h>
#include <stdint.h>
#include <stdio.h>

extern char fault_push, after_push, fault_pop, after_pop;
extern char fault_rsp_load, after_rsp_load, fault_rsp_exchange, after_rsp_exchange;
extern char fault_rsp_address_load, after_rsp_address_load, fault_rsp_address_store, after_rsp_address_store;
extern char fault_rsp_snapshot_reuse, after_rsp_snapshot_reuse;
extern char fault_rsp_snapshot_deferred, after_rsp_snapshot_deferred;
static unsigned seen, bad;

static LONG CALLBACK fault(EXCEPTION_POINTERS *p) {
  if (p->ExceptionRecord->ExceptionCode != EXCEPTION_ACCESS_VIOLATION) return EXCEPTION_CONTINUE_SEARCH;
  CONTEXT *c = p->ContextRecord;
  const uintptr_t sites[][3] = {
    {(uintptr_t)&fault_push, (uintptr_t)&after_push, 96},
    {(uintptr_t)&fault_pop, (uintptr_t)&after_pop, 96},
    {(uintptr_t)&fault_rsp_load, (uintptr_t)&after_rsp_load, 96},
    {(uintptr_t)&fault_rsp_exchange, (uintptr_t)&after_rsp_exchange, 96},
    {(uintptr_t)&fault_rsp_address_load, (uintptr_t)&after_rsp_address_load, 96},
    {(uintptr_t)&fault_rsp_address_store, (uintptr_t)&after_rsp_address_store, 96},
    {(uintptr_t)&fault_rsp_snapshot_reuse, (uintptr_t)&after_rsp_snapshot_reuse, 112},
    {(uintptr_t)&fault_rsp_snapshot_deferred, (uintptr_t)&after_rsp_snapshot_deferred, 128},
  };
  for (unsigned i = 0; i < sizeof(sites) / sizeof(sites[0]); ++i) {
    if (c->Rip != sites[i][0]) continue;
    ++seen;
    bad += c->Rsp != c->R10 - sites[i][2] || c->R9 != UINT64_C(0x1122334455667788);
    c->Rip = sites[i][1];
    return EXCEPTION_CONTINUE_EXECUTION;
  }
  return EXCEPTION_CONTINUE_SEARCH;
}

__attribute__((naked, noinline)) static void exercise(void *denied, uint64_t *data) {
  __asm__("movq %rsp,%r10\n\tlea -96(%rsp),%rsp\n\t"
          "movq (%rdx),%r9\n\t.globl fault_push,after_push\nfault_push:\n\tpushq (%rcx)\nafter_push:\n\t"
          "movq (%rdx),%r9\n\t.globl fault_pop,after_pop\nfault_pop:\n\tpopq (%rcx)\nafter_pop:\n\t"
          "movq (%rdx),%r9\n\t.globl fault_rsp_load,after_rsp_load\nfault_rsp_load:\n\tmovq (%rcx),%rsp\nafter_rsp_load:\n\t"
          "movq (%rdx),%r9\n\t.globl fault_rsp_exchange,after_rsp_exchange\nfault_rsp_exchange:\n\txchgq %rsp,(%rcx)\nafter_rsp_exchange:\n\t"
          "movq %rcx,%r11\n\tsubq %rsp,%r11\n\t"
          "movq (%rdx),%r9\n\t.globl fault_rsp_address_load,after_rsp_address_load\nfault_rsp_address_load:\n\tmovq (%rsp,%r11),%rax\nafter_rsp_address_load:\n\t"
          "movq (%rdx),%r9\n\t.globl fault_rsp_address_store,after_rsp_address_store\nfault_rsp_address_store:\n\tmovq %r9,(%rsp,%r11)\nafter_rsp_address_store:\n\t"
          "lea -16(%rsp),%rsp\n\tmovq (%rdx),%r9\n\tlock addq $0,(%rdx)\n\t"
          ".globl fault_rsp_snapshot_reuse,after_rsp_snapshot_reuse\nfault_rsp_snapshot_reuse:\n\tlock addq $0,(%rcx)\nafter_rsp_snapshot_reuse:\n\t"
          "lea -16(%rsp),%rsp\n\tmovq (%rdx),%r9\n\t"
          ".globl fault_rsp_snapshot_deferred,after_rsp_snapshot_deferred\nfault_rsp_snapshot_deferred:\n\tlock addq $0,(%rcx)\nafter_rsp_snapshot_deferred:\n\t"
          "lea 128(%rsp),%rsp\n\tret");
}

int main(void) {
  setvbuf(stdout, NULL, _IONBF, 0);
  void *denied = VirtualAlloc(NULL, 16384, MEM_RESERVE | MEM_COMMIT, PAGE_NOACCESS);
  PVOID handler = AddVectoredExceptionHandler(1, fault);
  if (!denied || !handler) return 2;
  uint64_t data = UINT64_C(0x1122334455667788);
  for (unsigned i = 0; i < 50; ++i) exercise(denied, &data);
  RemoveVectoredExceptionHandler(handler);
  VirtualFree(denied, 0, MEM_RELEASE);
  printf("RSP_RECOVERY seen=%u expected=400 bad=%u\n", seen, bad);
  return seen == 400 && !bad ? 0 : 1;
}
