#include <windows.h>
#include <stdint.h>
#include <stdio.h>
extern char fake_return_target;
__attribute__((naked,noinline)) unsigned fake_returns(unsigned count,void **target) {
  __asm__("xorl %eax,%eax\n1:\nmovq (%rdx),%r8\npushq %r8\nret\n.globl fake_return_target\nfake_return_target:\nincl %eax\ncmpl %ecx,%eax\njb 1b\nret");
}
__attribute__((naked,noinline)) unsigned recurse(unsigned count) {
  __asm__("testl %ecx,%ecx\njz 1f\nsubl $1,%ecx\nsubq $8,%rsp\ncallq recurse\naddq $8,%rsp\nincl %eax\nret\n1:\nxorl %eax,%eax\nret");
}
static DWORD WINAPI worker(void *unused) {
  (void)unused;void *target=&fake_return_target;
  unsigned a=recurse(150000),b=fake_returns(600000,&target);
  printf("CALLRET_STRESS recursion=%u expected=150000 synthetic_returns=%u expected=600000\n",a,b);
  return a!=150000||b!=600000;
}
int main(void) {
  setvbuf(stdout,NULL,_IONBF,0);HANDLE t=CreateThread(NULL,8*1024*1024,worker,0,STACK_SIZE_PARAM_IS_A_RESERVATION,0);
  if(!t||WaitForSingleObject(t,60000)!=WAIT_OBJECT_0)return 2;
  DWORD code=1;if(!GetExitCodeThread(t,&code))return 3;CloseHandle(t);
  printf("CALLRET_STRESS_RESULT bad=%lu\n",code);return code?1:0;
}
