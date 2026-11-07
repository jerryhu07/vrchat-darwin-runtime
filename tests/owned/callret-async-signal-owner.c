#include <windows.h>
#include <winternl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "memory-owner-peer.h"
typedef int64_t (*Gate)(uint64_t,uint64_t,uint64_t,uint64_t,uint64_t,uint64_t,uint64_t);
typedef LONG(WINAPI *Query)(HANDLE,const void*,unsigned,void*,SIZE_T,SIZE_T*);
typedef LONG(WINAPI *Unix)(uint64_t,unsigned,void*);
extern char fake_return_target;
__attribute__((naked,noinline)) unsigned fake_returns(unsigned count,void **target) {
  __asm__("xorl %eax,%eax\n1:\nmovq (%rdx),%r8\npushq %r8\nret\n.globl fake_return_target\nfake_return_target:\nincl %eax\ncmpl %ecx,%eax\njb 1b\nret");
}

__attribute__((naked,noinline)) void await_parent(volatile uint64_t *flag) {
  __asm__("1: movq (%rcx),%rax; testq %rax,%rax; jz 1b; ret");
}
static volatile LONG workers_ready,workers_exit;
static DWORD WINAPI live_worker(void* unused){(void)unused;InterlockedIncrement(&workers_ready);while(!workers_exit)Sleep(1);return 0;}
int main(void) {
 setvbuf(stdout,0,_IONBF,0);HANDLE workers[8];for(unsigned i=0;i<8;++i){workers[i]=CreateThread(0,0,live_worker,0,0,0);if(!workers[i])return 40;}
 while(workers_ready!=8)Sleep(1);
 const unsigned char bytes[]={0x57,0x56,0x48,0x89,0xc8,0x48,0x89,0xd7,0x4c,0x89,0xc6,0x4c,0x89,0xca,0x4c,0x8b,0x54,0x24,0x38,0x4c,0x8b,0x44,0x24,0x40,0x4c,0x8b,0x4c,0x24,0x48,0x0f,0x05,0x5e,0x5f,0xc3};
 void *gate_code=VirtualAlloc(0,16384,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE);DWORD old;
 if(!gate_code)return 10;memcpy(gate_code,bytes,sizeof(bytes));if(!VirtualProtect(gate_code,16384,PAGE_EXECUTE_READ,&old))return 11;Gate gate=(Gate)gate_code;
 int64_t fd=gate(319,(uint64_t)(uintptr_t)"fresh-thread",2,0,0,0,0);if(fd<0)return 12;gate(3,fd,0,0,0,0,0);
 HMODULE n=GetModuleHandleW(L"ntdll.dll");Query query=(Query)GetProcAddress(n,"NtQueryVirtualMemory");Unix *dispatch=(Unix*)GetProcAddress(n,"__wine_unix_call_dispatcher");
 const WCHAR path[]=L"\\??\\Z:\\Volumes\\unis500g\\vrchat-native-lab\\work\\runtime-contract\\memory-owner-peer.so";
 UNICODE_STRING name={sizeof(path)-2,sizeof(path),(WCHAR*)path};uint64_t handles[2];
 if(!query||!dispatch||query(GetCurrentProcess(),&name,1002,handles,sizeof(handles),0))return 13;
 FliMemoryPeer state={0};if((*dispatch)(handles[1],0,&state))return 14;

 if((*dispatch)(handles[1],19,&state))return 41;
 typedef int64_t(__attribute__((sysv_abi))*ForkFn)(void);ForkFn fork_fn=(ForkFn)(uintptr_t)state.result;
 volatile uint64_t* result=(void*)(uintptr_t)state.address;
 printf("FORK_CONTROL before fork=%llx\n",(unsigned long long)(uintptr_t)fork_fn);
 typedef int64_t(__attribute__((sysv_abi))*RaiseFn)(int);RaiseFn raise_fn=(RaiseFn)(uintptr_t)state.length;
 int64_t pid=fork_fn();
 if(pid==0){result[3]=0x1111;result[4]=gate(101,0,0,0,0,0,0);result[5]=raise_fn(19);void *target=&fake_return_target;result[6]=fake_returns(400000,&target);result[8]=1;await_parent(&result[9]);result[7]=0;result[0]=0xc001;result[1]=gate(39,0,0,0,0,0,0);result[2]=gate(186,0,0,0,0,0,0);gate(231,23,0,0,0,0,0);for(;;)YieldProcessor();}
 printf("FORK_CONTROL parent child=%lld\n",(long long)pid);
 int status=0;int64_t waited=-1;unsigned stop_ok=0,bus_ok=0,sent=0;for(unsigned i=0;i<1500;++i){if(result[8]&&!sent){Sleep(10);sent=1;gate(62,pid,7,0,0,0,0);}waited=gate(61,pid,(uint64_t)(uintptr_t)&status,1,0,0,0);if(waited==pid && status==0x137f){stop_ok=1;gate(101,7,pid,0,0,0,0);waited=0;}else if(waited==pid&&status==0x77f&&result[6]==400000){bus_ok=1;result[9]=1;gate(101,7,pid,0,0,0,0);waited=0;}else if(waited)break;Sleep(1);}
 unsigned passed=0,total=0;
 #define CHECK(n,v) do{unsigned ok=!!(v);++total;passed+=ok;printf("FORK_CONTROL %s %s\n",n,ok?"PASS":"FAIL");}while(0)
 CHECK("async-guest-bus-visible",bus_ok&&result[7]==0);CHECK("return-cache-guards-internal",result[6]==400000);CHECK("trace-me",result[3]==0x1111&&result[4]==0);CHECK("real-glibc-raise-stop",stop_ok);CHECK("raise-resumed",result[0]==0xc001&&result[5]==0);CHECK("parent-return",pid>0);CHECK("child-executed",result[0]==0xc001);CHECK("real-child-pid",result[1]==(uint64_t)pid);CHECK("child-reaped",waited==pid);CHECK("child-exit-status",status==(23<<8));CHECK("child-main-tid",result[0]==0xc001&&result[1]==result[2]);
 InterlockedExchange(&workers_exit,1);for(unsigned i=0;i<8;++i){WaitForSingleObject(workers[i],10000);CloseHandle(workers[i]);}
 if(waited!=pid || (status&0xff)==0x7f){gate(62,pid,9,0,0,0,0);gate(61,pid,(uint64_t)(uintptr_t)&status,0,0,0,0);}
 printf("FORK_CONTROL_RESULT %u/%u\n",passed,total);return passed==total?0:1;
}
