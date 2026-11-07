#include <windows.h>
#include <stdint.h>
#include <stdio.h>

/* Call the actual import with sentinels in every x64 nonvolatile GPR.
 * The second alignment exercises FEX's misaligned native-return stub. */
__attribute__((naked, noinline))
static unsigned check_call(void *function, const uintptr_t *args, unsigned misalign) {
  __asm__(
    "movq %rcx,%r11\n"
    "movq %rdx,%r10\n"
    "movl %r8d,%eax\n"
    "pushq %rbx\npushq %rbp\npushq %rsi\npushq %rdi\n"
    "pushq %r12\npushq %r13\npushq %r14\npushq %r15\n"
    "subq $88,%rsp\nsubq %rax,%rsp\nmovq %rax,64(%rsp)\n"
    "movq 32(%r10),%rax\nmovq %rax,32(%rsp)\n"
    "movq 40(%r10),%rax\nmovq %rax,40(%rsp)\n"
    "movq 0(%r10),%rcx\nmovq 8(%r10),%rdx\n"
    "movq 16(%r10),%r8\nmovq 24(%r10),%r9\n"
    "movq $0x11223301,%rbx\nmovq $0x11223302,%rbp\n"
    "movq $0x11223303,%rsi\nmovq $0x11223304,%rdi\n"
    "movq $0x11223305,%r12\nmovq $0x11223306,%r13\n"
    "movq $0x11223307,%r14\nmovq $0x11223308,%r15\n"
    "callq *%r11\n"
    "xorl %eax,%eax\n"
#define CHECK_REG(reg, value, bit) \
    "cmpq $" #value ",%" #reg "\nsetne %dl\nmovzbl %dl,%edx\n" \
    "shll $" #bit ",%edx\norl %edx,%eax\n"
    CHECK_REG(rbx, 0x11223301, 0)
    CHECK_REG(rbp, 0x11223302, 1)
    CHECK_REG(rsi, 0x11223303, 2)
    CHECK_REG(rdi, 0x11223304, 3)
    CHECK_REG(r12, 0x11223305, 4)
    CHECK_REG(r13, 0x11223306, 5)
    CHECK_REG(r14, 0x11223307, 6)
    CHECK_REG(r15, 0x11223308, 7)
#undef CHECK_REG
    "movq 64(%rsp),%r10\naddq $88,%rsp\naddq %r10,%rsp\n"
    "popq %r15\npopq %r14\npopq %r13\npopq %r12\n"
    "popq %rdi\npopq %rsi\npopq %rbp\npopq %rbx\nretq\n");
}

static unsigned callbacks;
static LRESULT CALLBACK callback(HWND hwnd, UINT level, WPARAM w, LPARAM l) {
  (void)hwnd; (void)w; (void)l;
  ++callbacks;
  return level < 2 ? CallWindowProcW(callback, NULL, level + 1, 0, 0) : 17;
}

int main(void) {
  setvbuf(stdout, NULL, _IONBF, 0);
  LARGE_INTEGER counter = {0};
  MEMORY_BASIC_INFORMATION info = {0};
  HANDLE event = CreateEventW(NULL, TRUE, FALSE, NULL);
  if (!event) return 2;
  struct {
    const char *name;
    void *function;
    uintptr_t args[6];
  } cases[] = {
    {"GetCurrentProcessId", GetCurrentProcessId, {0}},
    {"GetCurrentThreadId", GetCurrentThreadId, {0}},
    {"GetTickCount64", GetTickCount64, {0}},
    {"QueryPerformanceCounter", QueryPerformanceCounter, {(uintptr_t)&counter}},
    {"VirtualQuery", VirtualQuery, {(uintptr_t)&counter, (uintptr_t)&info, sizeof(info)}},
    {"WaitForSingleObject", WaitForSingleObject, {(uintptr_t)event, 0}},
    {"CallWindowProcW", CallWindowProcW, {(uintptr_t)callback, 0, 0, 0, 0}},
  };
  unsigned checks = 0, failures = 0;
  for (unsigned i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
    for (unsigned alignment = 0; alignment <= 8; alignment += 8) {
      unsigned mask = 0;
      for (unsigned round = 0; round < 64; ++round) {
        mask |= check_call(cases[i].function, cases[i].args, alignment);
        ++checks;
      }
      failures += mask != 0;
      printf("NATIVE_NONVOLATILE case=%s misalign=%u mask=%x\n", cases[i].name, alignment, mask);
    }
  }
  CloseHandle(event);
  printf("NATIVE_NONVOLATILE_RESULT checks=%u expected=896 failures=%u callbacks=%u expected=384\n",
         checks, failures, callbacks);
  return checks == 896 && !failures && callbacks == 384 ? 0 : 1;
}
