#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
static unsigned char *code;
static volatile LONG completed,errors;
static LRESULT CALLBACK callback(HWND h,UINT level,WPARAM w,LPARAM l) {
  (void)h;(void)w;(void)l;uint64_t sum=0;
  for(unsigned i=0;i<24000;++i){
    sum+=((uint32_t(*)(void))(code+16*i))();
    if(i==12000&&!level&&CallWindowProcW(callback,0,1,0,0)!=171)InterlockedIncrement(&errors);
  }
  if(sum!=287988000)InterlockedIncrement(&errors);
  InterlockedIncrement(&completed);return 171;
}
static DWORD WINAPI worker(void* p) {
  (void)p;for(unsigned r=0;r<3;++r)if(CallWindowProcW(callback,0,0,0,0)!=171)InterlockedIncrement(&errors);
  return 0;
}
int main(void) {
  setvbuf(stdout,0,_IONBF,0);DWORD old;
  code=VirtualAlloc(0,24000*16,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE);if(!code)return 2;
  for(uint32_t i=0;i<24000;++i){code[16*i]=0xb8;memcpy(code+16*i+1,&i,4);code[16*i+5]=0xc3;}
  if(!VirtualProtect(code,24000*16,PAGE_EXECUTE_READ,&old))return 3;
  HANDLE threads[2];for(unsigned i=0;i<2;++i){threads[i]=CreateThread(0,0,worker,0,0,0);if(!threads[i])return 4;}
  if(WaitForMultipleObjects(2,threads,TRUE,30000)!=WAIT_OBJECT_0)return 5;
  for(unsigned i=0;i<2;++i)CloseHandle(threads[i]);VirtualFree(code,0,MEM_RELEASE);
  printf("JIT_CALLBACK_LIFETIME_RESULT completed=%ld expected=12 errors=%ld\n",completed,errors);
  return completed==12&&!errors?0:6;
}
