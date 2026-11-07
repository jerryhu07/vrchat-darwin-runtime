#include <windows.h>
#include <bcrypt.h>
BOOLEAN WINAPI SystemFunction036(void *,ULONG);
static void report(const char *s,DWORD n){DWORD done;WriteFile(GetStdHandle(STD_OUTPUT_HANDLE),s,n,&done,0);}
static INIT_ONCE once=INIT_ONCE_STATIC_INIT;
__attribute__((naked)) static BOOL WINAPI initialize(PINIT_ONCE value,void *parameter,void **context){
 __asm__(".seh_proc initialize\n"
         "pushq %rbp\n.seh_pushreg %rbp\n"
         "subq $256,%rsp\n.seh_stackalloc 256\n.seh_endprologue\n"
         "xorq %rbp,%rbp\nmovq $0,%rax\nmovl $1,(%rax)\n"
         "addq $256,%rsp\npopq %rbp\nretq\n.seh_endproc\n");
}

static DWORD WINAPI worker(void *unused){
 (void)unused;
 __try {InitOnceExecuteOnce(&once,initialize,(void*)42,0);return 11;}
 __except(GetExceptionCode()==EXCEPTION_ACCESS_VIOLATION?EXCEPTION_EXECUTE_HANDLER:EXCEPTION_CONTINUE_SEARCH){report("INIT_ONCE_FAULT_HANDLED\n",24);}
 return 0;
}
void entry(void){
 report("EXCEPTION_CONTROL_ENTER\n",24);DWORD code=12;
 HANDLE thread=CreateThread(0,0,worker,0,0,0);
 if(!thread||WaitForSingleObject(thread,4000)!=WAIT_OBJECT_0||!GetExitCodeThread(thread,&code)||code)ExitProcess(13);
 CloseHandle(thread);report("EXCEPTION_CONTROL_DONE\n",24);ExitProcess(0);
}

int main(void) { entry(); return 0; }
