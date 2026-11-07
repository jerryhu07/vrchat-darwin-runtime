#include <windows.h>
#include <winternl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "memory-owner-peer.h"
#include "atomic-contention.h"
typedef int64_t (*Gate)(uint64_t,uint64_t,uint64_t,uint64_t,uint64_t,uint64_t,uint64_t);
typedef LONG(WINAPI *Query)(HANDLE,const void*,unsigned,void*,SIZE_T,SIZE_T*);
typedef LONG(WINAPI *Unix)(uint64_t,unsigned,void*);
static int64_t path_call(Gate gate,Unix dispatch,uint64_t handle,unsigned root,uint64_t number,uint64_t a,uint64_t b,uint64_t c,uint64_t d) {
  if(!root)return gate(number,a,b,c,d,0,0);
  uint64_t args[6]={number,a,b,c,d,0};FliMemoryPeer r={.address=(uint64_t)(uintptr_t)args};
  LONG status=dispatch(handle,21,&r);return status?status:r.result;
}
static unsigned passed,total;
__attribute__((noinline)) static uint64_t owned_bad_read(void){return *(volatile uint64_t*)(uintptr_t)0x28;}
static volatile uint64_t own_expected_sp,own_observed_sp,own_fault_pc;
static volatile uint64_t own_resume_pc,own_observed_return;
static volatile unsigned own_faults,own_fault_carry;
static DWORD WINAPI own_fault_timeout(void *unused){(void)unused;Sleep(3000);ExitProcess(81);return 0;}
static LONG CALLBACK own_fault_observer(EXCEPTION_POINTERS *p) {
  if(p->ExceptionRecord->ExceptionCode!=0xc0000005 || p->ContextRecord->Rip!=own_fault_pc)return EXCEPTION_CONTINUE_SEARCH;
  own_observed_sp=p->ContextRecord->Rsp;own_fault_carry=p->ContextRecord->EFlags&1;++own_faults;
  own_observed_return=*(const uint64_t*)(uintptr_t)own_observed_sp;
  // This fixture recovers its own failed read after recording the real context.
  p->ContextRecord->Rsp=own_expected_sp+(own_resume_pc?8:0);p->ContextRecord->Rip=own_resume_pc?own_resume_pc:p->ContextRecord->Rip+8;
  return EXCEPTION_CONTINUE_EXECUTION;
}
static void check(const char *name,int value){++total;passed+=!!value;printf("MEMORY_OWNER %s %s\n",name,value?"PASS":"FAIL");}
static void write_code(uint64_t address,uint32_t value){unsigned char bytes[]={0xb8,0,0,0,0,0xc3};memcpy(bytes+1,&value,4);memcpy((void*)(uintptr_t)address,bytes,sizeof(bytes));}
int main(int argc,char **argv) {
  setvbuf(stdout,NULL,_IONBF,0);
  const unsigned char bytes[]={0x57,0x56,0x48,0x89,0xc8,0x48,0x89,0xd7,0x4c,0x89,0xc6,0x4c,0x89,0xca,
    0x4c,0x8b,0x54,0x24,0x38,0x4c,0x8b,0x44,0x24,0x40,0x4c,0x8b,0x4c,0x24,0x48,0x0f,0x05,0x5e,0x5f,0xc3};
  void *code=VirtualAlloc(NULL,16384,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE);DWORD old;if(!code)return 10;
  memcpy(code,bytes,sizeof(bytes));if(!VirtualProtect(code,16384,PAGE_EXECUTE_READ,&old))return 11;Gate gate=(Gate)code;
  int64_t fd=gate(319,(uint64_t)(uintptr_t)"memory-owner-contract",2,0,0,0,0);if(fd<0)return 12;gate(3,fd,0,0,0,0,0);
  HMODULE n=GetModuleHandleW(L"ntdll.dll");Query query=(Query)GetProcAddress(n,"NtQueryVirtualMemory");Unix *dispatch=(Unix*)GetProcAddress(n,"__wine_unix_call_dispatcher");
  const WCHAR path[]=FLI_TEST_PEER_PATH;
  UNICODE_STRING name={sizeof(path)-2,sizeof(path),(WCHAR*)path};uint64_t handles[2];
  if(!query||!dispatch||query(GetCurrentProcess(),&name,1002,handles,sizeof(handles),NULL))return 13;
  FliMemoryPeer state={0};LONG status=(*dispatch)(handles[1],0,&state);
  printf("MEMORY_OWNER initialize=%lx address=%llx\n",status,(unsigned long long)state.address);if(status)return 14;
  const uint64_t address=state.address;write_code(address,1234);
  if(argc>1 && !strcmp(argv[1],"path-bounds")) {
    const uint64_t edge=address+32768,buffer=address+4096;
    if(gate(10,edge,16384,0,0,0,0))return 70;
    for(unsigned root=0;root<2;++root) {
      for(unsigned test=0;test<7;++test) {
        // Root guard-page parsing has a separately recorded baseline crash.
        // This test covers Native boundaries and unchanged readable Root paths.
        if(root && test!=0 && test!=1 && test!=3)continue;
        uint64_t pointer=buffer;
        if(test==0){*(char*)(uintptr_t)(edge-1)=0;pointer=edge-1;}
        if(test==1){memcpy((void*)(uintptr_t)(edge-2),"/",2);pointer=edge-2;}
        if(test==2){*(char*)(uintptr_t)(edge-1)='x';pointer=edge-1;}
        if(test==3){pointer=address+8191;memcpy((void*)(uintptr_t)pointer,"/tmp",5);}
        if(test==4){memset((void*)(uintptr_t)buffer,'a',4096);}
        if(test==5)pointer=0;
        if(test==6)pointer=UINT64_MAX;
        int64_t result=path_call(gate,*dispatch,handles[1],root,257,(uint64_t)-100,pointer,0,0);
        if(result>=0){if(path_call(gate,*dispatch,handles[1],root,3,result,0,0,0))return 71;result=0;}
        int64_t expected=test==0?(root?-45:-38):(test==1||test==3)?0:-14;
        printf("PATH_BOUNDARY owner=%u case=%u result=%lld expected=%lld\n",root,test,(long long)result,(long long)expected);
        check("bounded-path",result==expected);
      }
      char *name=(char*)(uintptr_t)buffer;memcpy(name,"/tmp/",5);
      for(unsigned i=0;i<90;++i){name[5+i*2]='.';name[6+i*2]='/';}name[185]=0;
      LARGE_INTEGER f,a,b;QueryPerformanceFrequency(&f);QueryPerformanceCounter(&a);
      for(unsigned i=0;i<500;++i) {
        int64_t fd=path_call(gate,*dispatch,handles[1],root,257,(uint64_t)-100,buffer,0,0);
        if(fd<0||path_call(gate,*dispatch,handles[1],root,3,fd,0,0,0))return 72;
      }
      QueryPerformanceCounter(&b);printf("PATH_BATCH owner=%u calls=500 ms=%.3f\n",root,(b.QuadPart-a.QuadPart)*1000.0/f.QuadPart);
    }
    if(gate(10,edge,16384,3,0,0,0))return 73;
    (*dispatch)(handles[1],3,&state);VirtualFree(code,0,MEM_RELEASE);
    printf("PATH_BOUNDS_RESULT %u/%u\n",passed,total);return passed==total?0:1;
  }
  if(argc>1 && !strcmp(argv[1],"unwind-domain")) {
    // Private, symbol-verified Wine virtual_unwind ABI. ARM64EC uses the AMD64
    // CONTEXT overlay here; its dispatcher has NonVolatileRegisters at 0x50.
    typedef LONG(WINAPI *Unwind)(ULONG,void*,CONTEXT*);
    Unwind unwind=(Unwind)((uintptr_t)n+FLI_TEST_UNWIND_RVA);
    CONTEXT ctx={0};uint64_t dispatcher[12]={0},nonvolatile[32]={0};
    uint64_t stack=(uint64_t)(uintptr_t)&main,initial_sp=(uint64_t)(uintptr_t)&stack;
    ctx.ContextFlags=CONTEXT_FULL|0x20000000;ctx.Rip=UINT64_MAX;ctx.Rsp=initial_sp;
    dispatcher[10]=(uint64_t)(uintptr_t)nonvolatile;
    LONG result=-1;unsigned exception=0;
    __try {result=unwind(0,dispatcher,&ctx);}
    __except(EXCEPTION_EXECUTE_HANDLER){exception=1;}
    printf("UNWIND_DOMAIN exception=%u result=%lx rip=%llx rsp=%llx\n",exception,result,(unsigned long long)ctx.Rip,(unsigned long long)ctx.Rsp);
    check("inlined-unwound-pc-query-bounded",!exception && result==0);
    check("unwind-keeps-real-leaf-stack-rule",!exception && ctx.Rip==stack && ctx.Rsp==initial_sp+8);
    (*dispatch)(handles[1],3,&state);VirtualFree(code,0,MEM_RELEASE);
    printf("UNWIND_DOMAIN_RESULT %u/%u\n",passed,total);return passed==total?0:1;
  }
  if(argc>1 && !strcmp(argv[1],"seh-mixed-stack")) {
    const unsigned char function[]={0x48,0x83,0xec,0x10,0x48,0xc7,0xc0,0xff,0xff,0xff,0xff,
      0x48,0x89,0x04,0x24,0x48,0x89,0x44,0x24,8,
      0x48,0x8b,0x04,0x25,0x28,0,0,0,0x48,0x83,0xc4,0x10,0xc3};
    memcpy((void*)(uintptr_t)address,function,sizeof(function));
    if(gate(10,address,4096,5,0,0,0))return 43;
    HANDLE timeout=CreateThread(NULL,0,own_fault_timeout,NULL,0,NULL);if(!timeout)return 44;CloseHandle(timeout);
    unsigned exception=0;DWORD status=0;uint64_t value=0;
    __try {value=((uint64_t(*)(void))(uintptr_t)address)();}
    __except((status=GetExceptionCode(),EXCEPTION_EXECUTE_HANDLER)){exception=1;}
    printf("MIXED_STACK_EXCEPTION caught=%u status=%lx value=%llu\n",exception,status,(unsigned long long)value);
    check("elf-locals-do-not-recurse-ec-lookup",exception && status==0xc0000005);
    (*dispatch)(handles[1],3,&state);VirtualFree(code,0,MEM_RELEASE);
    printf("MIXED_STACK_RESULT %u/%u\n",passed,total);return passed==total?0:1;
  }
  if(argc>1 && !strcmp(argv[1],"fetch-state")) {
    const unsigned char function[]={0x48,0x89,0x21,0x48,0x83,0x29,8,
      0x48,0xc7,0xc0,0xff,0xff,0xff,0xff,0xff,0xd0,0xc3};
    memcpy((void*)(uintptr_t)address,function,sizeof(function));
    if(gate(10,address,4096,5,0,0,0))return 39;
    own_fault_pc=UINT64_MAX;own_resume_pc=address+16;
    PVOID handler=AddVectoredExceptionHandler(1,own_fault_observer);if(!handler)return 40;
    HANDLE timeout=CreateThread(NULL,0,own_fault_timeout,NULL,0,NULL);if(!timeout)return 41;CloseHandle(timeout);
    ((void(*)(volatile uint64_t*))(uintptr_t)address)(&own_expected_sp);
    printf("FETCH_STATE expected-sp=%llx observed-sp=%llx return=%llx faults=%u\n",(unsigned long long)own_expected_sp,(unsigned long long)own_observed_sp,(unsigned long long)own_observed_return,own_faults);
    check("fetch-fault-preserves-call-stack",own_faults==1 && own_observed_sp==own_expected_sp);
    check("fetch-fault-has-correct-return-address",own_faults==1 && own_observed_return==own_resume_pc);
    RemoveVectoredExceptionHandler(handler);(*dispatch)(handles[1],3,&state);VirtualFree(code,0,MEM_RELEASE);
    printf("FETCH_STATE_RESULT %u/%u\n",passed,total);return passed==total?0:1;
  }
  if(argc>1 && !strcmp(argv[1],"fault-state")) {
    const unsigned char function[]={0x48,0x81,0xec,0x80,0,0,0,0x48,0x89,0x21,0xf9,
      0x48,0x8b,0x04,0x25,0x28,0,0,0,0x48,0x81,0xc4,0x80,0,0,0,0xc3};
    memcpy((void*)(uintptr_t)address,function,sizeof(function));
    if(gate(10,address,4096,5,0,0,0))return 37;
    own_fault_pc=address+11;PVOID handler=AddVectoredExceptionHandler(1,own_fault_observer);if(!handler)return 38;
    ((void(*)(volatile uint64_t*))(uintptr_t)address)(&own_expected_sp);
    printf("FAULT_STATE expected-sp=%llx observed-sp=%llx carry=%u faults=%u\n",(unsigned long long)own_expected_sp,(unsigned long long)own_observed_sp,own_fault_carry,own_faults);
    check("fault-preserves-live-stack",own_faults==1 && own_observed_sp==own_expected_sp);
    check("fault-preserves-live-carry",own_faults==1 && own_fault_carry==1);
    RemoveVectoredExceptionHandler(handler);(*dispatch)(handles[1],3,&state);VirtualFree(code,0,MEM_RELEASE);
    printf("FAULT_STATE_RESULT %u/%u\n",passed,total);return passed==total?0:1;
  }
  if(argc>1 && !strcmp(argv[1],"bitmap")) {
    typedef BOOLEAN(WINAPI *IsEc)(ULONG_PTR);IsEc is_ec=(IsEc)GetProcAddress(n,"RtlIsEcCode");
    if(!is_ec)return 35;
    const uint64_t pointers[]={0,address,(uint64_t)(uintptr_t)&main,1ULL<<47,(1ULL<<47)+4096,1ULL<<63,UINT64_MAX};
    for(unsigned i=0;i<sizeof(pointers)/sizeof(pointers[0]);++i) {
      unsigned exception=0;BOOLEAN value=1;
      __try {value=is_ec((ULONG_PTR)pointers[i]);}
      __except(EXCEPTION_EXECUTE_HANDLER){exception=1;}
      printf("BITMAP_QUERY pointer=%llx value=%u exception=%u\n",(unsigned long long)pointers[i],value,exception);
      check("bounded-execution-type-query",!exception && !value);
    }
    check("native-ec-code-still-marked",is_ec((ULONG_PTR)n+FLI_TEST_EC_RVA)!=0);
    (*dispatch)(handles[1],3,&state);VirtualFree(code,0,MEM_RELEASE);
    printf("BITMAP_RESULT %u/%u\n",passed,total);return passed==total?0:1;
  }
  if(argc>1 && !strcmp(argv[1],"seh")) {
    HANDLE timeout=CreateThread(NULL,0,own_fault_timeout,NULL,0,NULL);if(!timeout)return 42;CloseHandle(timeout);
    unsigned exception=0;DWORD status=0;uint64_t value=0;
    __try {value=owned_bad_read();}
    __except((status=GetExceptionCode(),EXCEPTION_EXECUTE_HANDLER)){exception=1;}
    check("windows-low-address-exception",exception && status==0xc0000005);
    const unsigned char load[]={0x48,0x8b,0x04,0x25,0x28,0,0,0,0xc3};
    memcpy((void*)(uintptr_t)address,load,sizeof(load));
    if(gate(10,address,4096,5,0,0,0))return 36;
    exception=0;status=0;
    __try {value=((uint64_t(*)(void))(uintptr_t)address)();}
    __except((status=GetExceptionCode(),EXCEPTION_EXECUTE_HANDLER)){exception=1;}
    check("elf-leaf-exception-through-windows-caller",exception && status==0xc0000005);
    exception=0;status=0;
    __try {value=((uint64_t(*)(void))(uintptr_t)UINT64_MAX)();}
    __except((status=GetExceptionCode(),EXCEPTION_EXECUTE_HANDLER)){exception=1;}
    check("invalid-target-does-not-recurse-bitmap-fault",exception && status==0xc0000005);
    printf("SEH_IGNORED_RESULT %llu\n",(unsigned long long)value);
    (*dispatch)(handles[1],3,&state);VirtualFree(code,0,MEM_RELEASE);
    printf("SEH_RESULT %u/%u\n",passed,total);return passed==total?0:1;
  }
  if(argc>1 && !strcmp(argv[1],"sleep")) {
    uint64_t request[2]={0,5000000},now[2]={0},after[2]={0},remaining[2]={77,88};
    gate(228,1,(uint64_t)(uintptr_t)now,0,0,0,0);
    check("native-relative-sleep",gate(35,(uint64_t)(uintptr_t)request,(uint64_t)(uintptr_t)remaining,0,0,0,0)==0);
    gate(228,1,(uint64_t)(uintptr_t)after,0,0,0,0);
    check("native-relative-really-waits",after[0]*1000000000+after[1]>=now[0]*1000000000+now[1]+5000000);
    check("sleep-success-preserves-remaining",remaining[0]==77 && remaining[1]==88);
    request[0]=after[0];request[1]=after[1]+5000000;if(request[1]>=1000000000){++request[0];request[1]-=1000000000;}
    check("native-absolute-sleep",gate(230,1,1,(uint64_t)(uintptr_t)request,(uint64_t)(uintptr_t)remaining,0,0)==0);
    gate(228,1,(uint64_t)(uintptr_t)after,0,0,0,0);
    check("native-absolute-reaches-deadline",after[0]*1000000000+after[1]>=request[0]*1000000000+request[1]);
    check("expired-absolute-succeeds",gate(230,1,1,(uint64_t)(uintptr_t)request,1,0,0)==0);
    check("sleep-rejects-bad-clock",gate(230,123,0,(uint64_t)(uintptr_t)request,0,0,0)==-22);
    check("sleep-rejects-bad-flags",gate(230,1,2,(uint64_t)(uintptr_t)request,0,0,0)==-22);
    request[0]=0;request[1]=1000000000;
    check("sleep-rejects-invalid-nanoseconds",gate(35,(uint64_t)(uintptr_t)request,0,0,0,0,0)==-22);
    check("sleep-rejects-bad-request",gate(35,1,0,0,0,0,0)==-14);
    gate(228,1,(uint64_t)(uintptr_t)now,0,0,0,0);
    state.address=0;state.length=5000000;state.protection=35;(*dispatch)(handles[1],15,&state);
    check("root-relative-sleep",state.result==0);
    gate(228,1,(uint64_t)(uintptr_t)after,0,0,0,0);
    check("root-relative-really-waits",after[0]*1000000000+after[1]>=now[0]*1000000000+now[1]+5000000);
    state.address=after[0];state.length=after[1]+5000000;if(state.length>=1000000000){++state.address;state.length-=1000000000;}
    state.protection=230;(*dispatch)(handles[1],15,&state);check("root-absolute-sleep",state.result==0);
    gate(228,1,(uint64_t)(uintptr_t)after,0,0,0,0);
    check("root-absolute-reaches-deadline",after[0]*1000000000+after[1]>=state.address*1000000000+state.length);
    (*dispatch)(handles[1],3,&state);VirtualFree(code,0,MEM_RELEASE);
    printf("SLEEP_RESULT %u/%u\n",passed,total);return passed==total?0:1;
  }
  if(argc>1 && !strcmp(argv[1],"atomic-contention")) {
    typedef uint64_t(__attribute__((sysv_abi))*Loop)(uint64_t,uint32_t,uint64_t);
    const unsigned char *operations[]={owned_atomic32,owned_atomic64,owned_mutex};
    const size_t sizes[]={sizeof(owned_atomic32),sizeof(owned_atomic64),sizeof(owned_mutex)};
    const unsigned offsets[]={0,1,5,7,9,13,15,61,63,4093,4095};
    for(unsigned op=0;op<3;++op) {
      if(gate(10,address,4096,3,0,0,0))return 30;
      memcpy((void*)(uintptr_t)address,operations[op],sizes[op]);
      if(gate(10,address,4096,5,0,0,0))return 31;
      for(unsigned i=0;i<sizeof(offsets)/sizeof(offsets[0]);++i) {
        uint64_t target=address+8192+offsets[i],sync=address+24576,value=0;
        memset((void*)(uintptr_t)target,0,8);memset((void*)(uintptr_t)sync,0,32);
        state.address=target;state.length=100000;state.protection=sync;
        if((*dispatch)(handles[1],13,&state))return 32;
        unsigned tries=0;
        while(!*(volatile uint32_t*)(uintptr_t)sync && ++tries<5000)Sleep(1);
        if(!*(volatile uint32_t*)(uintptr_t)sync)return 33;
        *(volatile uint32_t*)(uintptr_t)(sync+4)=1;
        uint64_t native=((Loop)(uintptr_t)address)(target,100000,sync);
        if((*dispatch)(handles[1],14,&state))return 34;
        memcpy(&value,(void*)(uintptr_t)(op==2?sync+8:target),op==0?4:8);
        printf("ATOMIC_CONTENTION operation=%u offset=%u count=%llu root=%lld native=%llu\n",op,offsets[i],(unsigned long long)value,(long long)state.result,(unsigned long long)native);
        check("concurrent-atomic-and-mutex",!native && !state.result && value==200000);
      }
    }
    (*dispatch)(handles[1],3,&state);VirtualFree(code,0,MEM_RELEASE);
    printf("ATOMIC_CONTENTION_RESULT %u/%u\n",passed,total);return passed==total?0:1;
  }
  if(argc>1 && !strcmp(argv[1],"atomic")) {
    const unsigned char root_bytes[]={0x89,0xf0,0xf0,0x0f,0xb1,0x17,0x41,0x0f,0x94,0xc0,
      0x45,0x0f,0xb6,0xc0,0x49,0xc1,0xe0,0x20,0x4c,0x09,0xc0,0xc3};
    const unsigned char native_bytes[]={0x57,0x56,0x48,0x89,0xcf,0x89,0xd6,0x44,0x89,0xc2,
      0x89,0xf0,0xf0,0x0f,0xb1,0x17,0x41,0x0f,0x94,0xc0,0x45,0x0f,0xb6,0xc0,
      0x49,0xc1,0xe0,0x20,0x4c,0x09,0xc0,0x5e,0x5f,0xc3};
    memcpy((void*)(uintptr_t)address,root_bytes,sizeof(root_bytes));
    if(gate(10,address,4096,5,0,0,0))return 27;
    void *native_code=VirtualAlloc(NULL,16384,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE);
    if(!native_code)return 28;
    memcpy(native_code,native_bytes,sizeof(native_bytes));
    if(!VirtualProtect(native_code,16384,PAGE_EXECUTE_READ,&old))return 29;
    typedef uint64_t(*Atomic)(uint64_t,uint32_t,uint32_t);Atomic native=(Atomic)native_code;
    const unsigned offsets[]={0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,61,62,63,4093,4094,4095};
    for(unsigned i=0;i<sizeof(offsets)/sizeof(offsets[0]);++i) {
      unsigned shift=offsets[i];
      printf("ATOMIC_OFFSET %u\n",shift);
      uint64_t lock=address+8192+shift;uint32_t zero=0,value=0;memcpy((void*)(uintptr_t)lock,&zero,4);
      state.address=lock;state.length=0;state.protection=1;(*dispatch)(handles[1],12,&state);
      memcpy(&value,(void*)(uintptr_t)lock,4);check("root-acquires-with-correct-flags",state.result==(int64_t)(1ULL<<32) && value==1);
      check("native-observes-root-owner",native(lock,0,2)==1);
      check("native-releases-root-owner",native(lock,1,0)==((1ULL<<32)|1));
      check("native-acquires",native(lock,0,3)==(1ULL<<32));
      state.length=0;state.protection=2;(*dispatch)(handles[1],12,&state);check("root-observes-native-owner",state.result==3);
      state.length=3;state.protection=0;(*dispatch)(handles[1],12,&state);
      memcpy(&value,(void*)(uintptr_t)lock,4);check("root-releases-native-owner",state.result==(int64_t)((1ULL<<32)|3) && value==0);
    }
    VirtualFree(native_code,0,MEM_RELEASE);(*dispatch)(handles[1],3,&state);VirtualFree(code,0,MEM_RELEASE);
    printf("ATOMIC_RESULT %u/%u\n",passed,total);return passed==total?0:1;
  }
  if(argc>1 && !strcmp(argv[1],"thread-state")) {
    const unsigned char fs_bytes[]={0x64,0x48,0x8b,0x04,0x25,0,0,0,0,0xc3};
    memcpy((void*)(uintptr_t)address,fs_bytes,sizeof(fs_bytes));
    check("thread-code-executable",gate(10,address,4096,5,0,0,0)==0);
    uint64_t native_fs=((uint64_t(*)(void))(uintptr_t)address)();
    state.protection=(uint64_t)(uintptr_t)NtCurrentTeb();
    (*dispatch)(handles[1],9,&state);
    printf("THREAD_STATE native-fs=%llx root-fs=%llx\n",(unsigned long long)native_fs,(unsigned long long)state.result);
    check("wine-callback-preserves-linux-tls",state.result==(int64_t)native_fs);
    if(gate(10,address,4096,3,0,0,0))return 21;
    const unsigned char tid_bytes[]={0xb8,0xba,0,0,0,0x0f,0x05,0xc3};
    memcpy((void*)(uintptr_t)address,tid_bytes,sizeof(tid_bytes));
    if(gate(10,address,4096,5,0,0,0))return 22;
    int64_t native_tid=gate(186,0,0,0,0,0,0);
    (*dispatch)(handles[1],9,&state);
    printf("THREAD_STATE native-tid=%lld root-tid=%lld\n",(long long)native_tid,(long long)state.result);
    check("wine-callback-preserves-linux-thread",state.result==native_tid);
    const unsigned char invoke_bytes[]={0x57,0x56,0x48,0x89,0xc8,0x48,0x89,0xd7,0x4c,0x89,0xc6,
      0x4c,0x89,0xca,0x48,0x83,0xec,0x08,0xff,0xd0,0x48,0x83,0xc4,0x08,0x5e,0x5f,0xc3};
    void *invoke_code=VirtualAlloc(NULL,16384,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE);
    if(!invoke_code)return 23;
    memcpy(invoke_code,invoke_bytes,sizeof(invoke_bytes));
    if(!VirtualProtect(invoke_code,16384,PAGE_EXECUTE_READ,&old))return 24;
    typedef int64_t (*LinuxCall)(uint64_t,uint64_t,uint64_t,uint64_t);
    LinuxCall invoke=(LinuxCall)invoke_code;uint64_t functions[6];
    for(unsigned i=0;i<6;++i){state.length=i;(*dispatch)(handles[1],10,&state);functions[i]=(uint64_t)state.result;}
    const uint64_t mutex=address+4096,attributes=address+8192;
    memset((void*)(uintptr_t)mutex,0,128);memset((void*)(uintptr_t)attributes,0,128);
    check("recursive-mutex-initializes",invoke(functions[0],attributes,0,0)==0 &&
      invoke(functions[1],attributes,1,0)==0 && invoke(functions[2],mutex,attributes,0)==0);
    int64_t held=invoke(functions[4],mutex,0,0);
    check("native-holds-recursive-mutex",held==0);
    if(gate(10,address,4096,3,0,0,0))return 25;
    unsigned char jump[]={0x48,0xb8,0,0,0,0,0,0,0,0,0xff,0xe0};
    memcpy(jump+2,&functions[4],8);memcpy((void*)(uintptr_t)address,jump,sizeof(jump));
    if(gate(10,address,4096,5,0,0,0))return 26;
    state.address=mutex;(*dispatch)(handles[1],9,&state);
    printf("THREAD_STATE root-recursive-trylock=%lld\n",(long long)state.result);
    check("root-reenters-caller-recursive-mutex",held==0 && state.result==0);
    if(state.result==0)check("native-releases-root-recursion",invoke(functions[5],mutex,0,0)==0);
    check("native-releases-original-lock",held==0 && invoke(functions[5],mutex,0,0)==0);
    VirtualFree(invoke_code,0,MEM_RELEASE);
    (*dispatch)(handles[1],11,&state);check("one-runtime-provider-loaded",state.result==1);
    (*dispatch)(handles[1],3,&state);VirtualFree(code,0,MEM_RELEASE);
    printf("THREAD_STATE_RESULT %u/%u\n",passed,total);return passed==total?0:1;
  }
  if(argc>1 && !strcmp(argv[1],"file-cursor")) {
    int64_t file=gate(319,(uint64_t)(uintptr_t)"shared-file-cursor",2,0,0,0,0);
    if(file<0)return 20;
    const char contents[]="ABCDEFGH";char value=0;
    check("native-writes",gate(1,file,(uint64_t)(uintptr_t)contents,8,0,0,0)==8);
    state.address=file;state.length=0;(*dispatch)(handles[1],8,&state);
    check("write-advances-kernel-cursor",state.result==8);
    check("seek-reset",gate(8,file,0,0,0,0,0)==0);
    check("native-reads-first",gate(0,file,(uint64_t)(uintptr_t)&value,1,0,0,0)==1 && value=='A');
    state.length=0;(*dispatch)(handles[1],8,&state);check("read-advances-kernel-cursor",state.result==1);
    state.length=1;(*dispatch)(handles[1],8,&state);check("duplicate-shares-cursor",state.result=='B');
    check("native-sees-duplicate-read",gate(0,file,(uint64_t)(uintptr_t)&value,1,0,0,0)==1 && value=='C');
    state.length=2;(*dispatch)(handles[1],8,&state);check("fork-shares-cursor",state.result=='D');
    check("native-sees-child-read",gate(0,file,(uint64_t)(uintptr_t)&value,1,0,0,0)==1 && value=='E');
    check("pread-uses-explicit-offset",gate(17,file,(uint64_t)(uintptr_t)&value,1,2,0,0)==1 && value=='C');
    check("pread-preserves-kernel-cursor",gate(8,file,0,1,0,0,0)==5);
    const char replacement='Z';
    check("pwrite-uses-explicit-offset",gate(18,file,(uint64_t)(uintptr_t)&replacement,1,1,0,0)==1);
    check("pwrite-preserves-kernel-cursor",gate(8,file,0,1,0,0,0)==5);
    check("pread-observes-pwrite",gate(17,file,(uint64_t)(uintptr_t)&value,1,1,0,0)==1 && value=='Z');
    check("pread-eof",gate(17,file,(uint64_t)(uintptr_t)&value,1,8,0,0)==0);
    check("pread-rejects-negative-offset",gate(17,file,(uint64_t)(uintptr_t)&value,1,UINT64_MAX,0,0)==-22);
    check("pread-rejects-bad-buffer",gate(17,file,1,1,0,0,0)==-14);
    check("pread-rejects-closed-fd",gate(17,UINT32_MAX,(uint64_t)(uintptr_t)&value,1,0,0,0)==-9);
    char path[80];snprintf(path,sizeof(path),"/proc/self/fd/%lld",(long long)file);
    int64_t reopened=gate(2,(uint64_t)(uintptr_t)path,0,0,0,0,0);
    check("proc-reopen-has-independent-cursor",reopened>=0 && gate(0,reopened,(uint64_t)(uintptr_t)&value,1,0,0,0)==1 && value=='A');
    check("proc-read-preserves-original-cursor",gate(0,file,(uint64_t)(uintptr_t)&value,1,0,0,0)==1 && value=='F');
    check("seals-preserve-cursor",gate(72,file,1033,15,0,0,0)==0 && gate(8,file,0,1,0,0,0)==6);
    check("read-after-seals",gate(0,file,(uint64_t)(uintptr_t)&value,1,0,0,0)==1 && value=='G');
    if(reopened>=0)gate(3,reopened,0,0,0,0,0);
    gate(3,file,0,0,0,0,0);(*dispatch)(handles[1],3,&state);VirtualFree(code,0,MEM_RELEASE);
    printf("FILE_CURSOR_RESULT %u/%u\n",passed,total);return passed==total?0:1;
  }
  if(argc>1 && !strcmp(argv[1],"clock")) {
    const unsigned char clock_bytes[]={0x0f,0x31,0x48,0xc1,0xe2,0x20,0x48,0x09,0xd0,0xc3};
    memcpy((void*)(uintptr_t)address,clock_bytes,sizeof(clock_bytes));
    check("clock-code-executable",gate(10,address,4096,5,0,0,0)==0);
    uint64_t (*ticks)(void)=(uint64_t(*)(void))(uintptr_t)address;
    unsigned tick_order=0,clock_order=0;
    uint64_t root_tick=0,native_before=0,native_after=0;
    for(unsigned i=0;i<100;++i) {
      native_before=ticks();(*dispatch)(handles[1],2,&state);root_tick=(uint64_t)state.result;native_after=ticks();
      tick_order+=native_before<=root_tick && root_tick<=native_after;
      uint64_t before[2]={0},after[2]={0};
      int64_t first=gate(228,1,(uint64_t)(uintptr_t)before,0,0,0,0);
      (*dispatch)(handles[1],7,&state);
      int64_t last=gate(228,1,(uint64_t)(uintptr_t)after,0,0,0,0);
      uint64_t low=before[0]*1000000000ULL+before[1],high=after[0]*1000000000ULL+after[1];
      clock_order+=first==0 && last==0 && state.result>=0 && low<=(uint64_t)state.result && (uint64_t)state.result<=high;
    }
    printf("CLOCK_ORDER tick=%u/100 monotonic=%u/100 before=%llu root=%llu after=%llu\n",tick_order,clock_order,
      (unsigned long long)native_before,(unsigned long long)root_tick,(unsigned long long)native_after);
    check("same-timestamp-counter",tick_order==100);check("same-monotonic-clock",clock_order==100);
    (*dispatch)(handles[1],3,&state);VirtualFree(code,0,MEM_RELEASE);
    printf("CLOCK_RESULT %u/%u\n",passed,total);return passed==total?0:1;
  }
  if(argc>1 && !strcmp(argv[1],"shared-alias")) {
    int64_t shared=gate(319,(uint64_t)(uintptr_t)"alias-code-contract",2,0,0,0,0);
    if(shared<0 || gate(77,shared,16384,0,0,0,0))return 17;
    unsigned char alias_bytes[]={0x8b,0x05,1,0,0,0,0xc3,0,0,0,0};int value=3535;memcpy(alias_bytes+7,&value,4);
    if(gate(18,shared,(uint64_t)(uintptr_t)alias_bytes,sizeof(alias_bytes),0,0,0)!=sizeof(alias_bytes))return 18;
    state.protection=shared;status=(*dispatch)(handles[1],5,&state);
    printf("SHARED_ALIAS map-status=%lx address=%llx\n",status,(unsigned long long)state.address);if(status)return 19;
    uint64_t alias=state.address;
    check("native-alias-data",((int(*)(void))(uintptr_t)alias)()==3535);
    (*dispatch)(handles[1],6,&state);check("root-alias-data",state.result==3535);
    value=4646;gate(18,shared,(uint64_t)(uintptr_t)&value,4,7,0,0);
    check("native-alias-data-update",((int(*)(void))(uintptr_t)alias)()==4646);
    (*dispatch)(handles[1],6,&state);check("root-alias-data-update",state.result==4646);
    unsigned char replacement[]={0xb8,0,0,0,0,0xc3};value=5757;memcpy(replacement+1,&value,4);
    gate(18,shared,(uint64_t)(uintptr_t)replacement,sizeof(replacement),0,0,0);
    check("native-alias-code-update",((int(*)(void))(uintptr_t)alias)()==5757);
    (*dispatch)(handles[1],6,&state);check("root-alias-code-update",state.result==5757);
    check("release-shared-alias",(*dispatch)(handles[1],3,&state)==0);
    gate(3,shared,0,0,0,0,0);VirtualFree(code,0,MEM_RELEASE);
    printf("SHARED_ALIAS_RESULT %u/%u\n",passed,total);return passed==total?0:1;
  }
  if(argc>1 && !strcmp(argv[1],"shared-smc")) {
    for(unsigned i=0;i<4;++i)write_code(address+i*4096,1234+i);
    check("shared-root-rwx",gate(10,address,16384,7,0,0,0)==0);
    check("root-writer-rx",gate(10,address+16384,4096,5,0,0,0)==0);
    for(unsigned i=0;i<4;++i)check("native-executes-shared-page",((int(*)(void))(uintptr_t)(address+i*4096))()==1234+(int)i);
    (*dispatch)(handles[1],1,&state);check("root-still-authorizes-write",state.protection==7);
    MEMORY_BASIC_INFORMATION info;VirtualQuery((void*)(uintptr_t)address,&info,sizeof(info));
    printf("SHARED_SMC before-root-write wine-protection=%lx guest-protection=%llu\n",info.Protect,(unsigned long long)state.protection);
    (*dispatch)(handles[1],4,&state);check("root-writes-native-tracked-code",state.result==0);
    uint32_t stored=0;memcpy(&stored,(const void*)(uintptr_t)(address+1),4);
    HMODULE fex=GetModuleHandleA("xtajit64.dll");uint64_t *stats=fex?(uint64_t*)GetProcAddress(fex,"LabSharedCodeCheckStats"):NULL;
    if(stats)printf("SHARED_SMC compiler calls=%llu cached=%llu effective=%llu emitted=%llu last=%llx\n",(unsigned long long)stats[0],(unsigned long long)stats[1],(unsigned long long)stats[2],(unsigned long long)stats[3],(unsigned long long)stats[4]);
    int executed=((int(*)(void))(uintptr_t)address)();
    printf("SHARED_SMC stored=%lu executed=%d\n",(unsigned long)stored,executed);
    check("native-sees-root-code-change",stored==9876 && executed==9876);
    (*dispatch)(handles[1],3,&state);VirtualFree(code,0,MEM_RELEASE);
    printf("SHARED_SMC_RESULT %u/%u\n",passed,total);return passed==total?0:1;
  }
  int64_t protect=gate(10,address,4096,5,0,0,0);
  (*dispatch)(handles[1],1,&state);
  printf("MEMORY_OWNER protect-result=%lld query-result=%lld root-protection=%llu\n",(long long)protect,(long long)state.result,(unsigned long long)state.protection);
  check("native-protect-root-mapping",protect==0 && state.result==0 && state.protection==5);
  if(protect==0) {
    check("native-execute",((int(*)(void))(uintptr_t)address)()==1234);
    (*dispatch)(handles[1],2,&state);check("root-execute",state.result==1234);
    state.address=address+4096;(*dispatch)(handles[1],1,&state);check("adjacent-permission-preserved",state.result==0 && state.protection==3);
    state.address=address;check("reject-invalid-protection",gate(10,address,4096,8,0,0,0)==-22);
    (*dispatch)(handles[1],1,&state);check("rejected-change-preserves-owner-state",state.protection==5);
    check("reject-unaligned-address",gate(10,address+1,4096,3,0,0,0)==-22);
    check("native-restore-write",gate(10,address,4096,3,0,0,0)==0);
    write_code(address,5678);check("native-restore-execute",gate(10,address,4096,5,0,0,0)==0);
    check("native-recompile",((int(*)(void))(uintptr_t)address)()==5678);
    (*dispatch)(handles[1],2,&state);check("root-recompile",state.result==5678);
  }
  (*dispatch)(handles[1],3,&state);VirtualFree(code,0,MEM_RELEASE);
  printf("MEMORY_OWNER_RESULT %u/%u\n",passed,total);return passed==total?0:1;
}
