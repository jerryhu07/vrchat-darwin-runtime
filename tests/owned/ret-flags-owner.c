#include <windows.h>
#include <stdint.h>
#include <stdio.h>
__attribute__((naked,noinline)) void ret_leaf(void) { __asm__("movl $1234,%eax\nret"); }
__attribute__((naked,noinline)) uint64_t direct_flags(uint64_t flags) {
  __asm__("subq $40,%rsp\npushq %rcx\npopfq\ncallq ret_leaf\npushfq\npopq %rax\naddq $40,%rsp\nret");
}
__attribute__((naked,noinline)) uint64_t indirect_flags(uint64_t flags,void (*fn)(void)) {
  __asm__("movq %rdx,%r11\nsubq $40,%rsp\npushq %rcx\npopfq\ncallq *%r11\npushfq\npopq %rax\naddq $40,%rsp\nret");
}
static unsigned seen,bad;
static void check(unsigned callback) {
  const unsigned bits[]={0,2,4,6,7,11};
  for(unsigned v=0;v<64;++v) {
    uint64_t flags=0x202;for(unsigned i=0;i<6;++i)flags|=((v>>i)&1ULL)<<bits[i];
    uint64_t a=direct_flags(flags)&0x8d5,b=indirect_flags(flags,ret_leaf)&0x8d5;
    seen+=2;bad+=(a!=(flags&0x8d5))+(b!=(flags&0x8d5));
    if(a!=(flags&0x8d5)||b!=(flags&0x8d5))printf("RET_FLAGS_BAD callback=%u expected=%llx direct=%llx indirect=%llx\n",callback,(unsigned long long)(flags&0x8d5),(unsigned long long)a,(unsigned long long)b);
  }
}
static BOOL CALLBACK inside(PINIT_ONCE once,PVOID param,PVOID *context) { (void)once;(void)param;(void)context;check(1);return TRUE; }
int main(void) {
  setvbuf(stdout,NULL,_IONBF,0);check(0);INIT_ONCE once=INIT_ONCE_STATIC_INIT;
  if(!InitOnceExecuteOnce(&once,inside,0,0))return 2;
  printf("RET_FLAGS_RESULT seen=%u expected=256 bad=%u\n",seen,bad);return seen!=256||bad;
}
