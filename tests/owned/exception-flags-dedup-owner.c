#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
static volatile DWORD expected,seen,bad;static volatile uintptr_t fault_pc;
static LONG CALLBACK fault(EXCEPTION_POINTERS* p){if(p->ExceptionRecord->ExceptionCode!=0xc0000005||p->ContextRecord->Rip!=fault_pc)return EXCEPTION_CONTINUE_SEARCH;++seen;DWORD got=p->ContextRecord->EFlags&0xcd5;printf("EXCEPTION_FLAGS_OBS case=%lu expected=%lx got=%lx\n",seen,expected&0xcd5,got);if(got!=(expected&0xcd5)){++bad;printf("EXCEPTION_FLAGS mismatch expected=%lx got=%lx\n",expected&0xcd5,got);}p->ContextRecord->Rip+=2;return EXCEPTION_CONTINUE_EXECUTION;}
__attribute__((naked,noinline)) void owned_memory(uint64_t* p){__asm__("movl $200000,%r8d\n\t1:\n\t.rept 8\n\tmovq (%rcx),%rax\n\tmovq %rax,8(%rcx)\n\t.endr\n\tdecl %r8d\n\tjnz 1b\n\tret");}
static void(*volatile memory_fn)(uint64_t*)=owned_memory;
static int run(const unsigned char* arithmetic,unsigned size,unsigned char* code,void* denied){
 // First obtain the architectural result. The faulting replay has no PUSHFQ
 // between the flag writer and fault, so it cannot refresh a stale NZCV cache.
 const unsigned char warm[]={0x45,0x31,0xc9,0x44,0x8b,0x02,0x44,0x8b,0x02};
 const unsigned char save[]={0x9c,0x41,0x58,0x44,0x89,0x02};
 const unsigned char load[]={0x44,0x8b,0x02};
 for(unsigned replay=0;replay<2;++replay){
  DWORD old;if(!VirtualProtect(code,16384,PAGE_READWRITE,&old))return 0;
  unsigned n=0;memcpy(code+n,warm,sizeof(warm));n+=sizeof(warm);memcpy(code+n,arithmetic,size);n+=size;
  if(!replay){memcpy(code+n,save,sizeof(save));n+=sizeof(save);}
  else {for(unsigned i=0;i<4;++i){memcpy(code+n,load,sizeof(load));n+=sizeof(load);}fault_pc=(uintptr_t)(code+n);code[n++]=0x8b;code[n++]=0x01;}
  code[n++]=0xfc;code[n++]=0xc3;
  if(!VirtualProtect(code,16384,PAGE_EXECUTE_READ,&old))return 0;FlushInstructionCache(GetCurrentProcess(),code,n);
  ((void(*)(void*,volatile DWORD*))code)(denied,&expected);
 }
 return 1;
}
int main(void){setvbuf(stdout,0,_IONBF,0);LARGE_INTEGER f,a,b;QueryPerformanceFrequency(&f);uint64_t data[2]={0x12345678,0};for(unsigned r=0;r<3;++r){QueryPerformanceCounter(&a);memory_fn(data);QueryPerformanceCounter(&b);printf("RAW_FLAGS_MEMORY round=%u ms=%.3f result=%llx\n",r,(b.QuadPart-a.QuadPart)*1000.0/f.QuadPart,(unsigned long long)data[1]);if(data[1]!=data[0])return 2;}
 unsigned char* code=VirtualAlloc(0,16384,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE);void* denied=VirtualAlloc(0,16384,MEM_RESERVE|MEM_COMMIT,PAGE_NOACCESS);PVOID handler=AddVectoredExceptionHandler(1,fault);if(!code||!denied||!handler)return 3;
 for(unsigned sub=0;sub<2;++sub)for(unsigned i=0;i<256;++i){unsigned char bytes[]={0xb8,0,0,0,0,0x83,0xc0,0x11};uint32_t v=(i&1)?0xffffff00u+i:0x7fffff00u+i;memcpy(bytes+1,&v,4);if(sub)bytes[6]=0xe8;if(!run(bytes,sizeof(bytes),code,denied))return 4;}
 const unsigned char inc[]={0xf9,0xb8,0x0f,0,0,0,0xff,0xc0};const unsigned char dec[]={0xf8,0xb8,0x10,0,0,0,0xff,0xc8};const unsigned char sahf[]={0xb8,0,0xd5,0,0,0x9e};const unsigned char df[]={0xb8,0xff,0xff,0xff,0x7f,0x83,0xc0,1,0xfd};
 if(!run(inc,sizeof(inc),code,denied)||!run(dec,sizeof(dec),code,denied)||!run(sahf,sizeof(sahf),code,denied)||!run(df,sizeof(df),code,denied))return 5;
 const unsigned char carry[][6]={{0xf9,0xf5,0x90,0x90,0x90,0x90},{0xf8,0xf5,0x90,0x90,0x90,0x90},{0xf9,0xf5,0xf5,0x90,0x90,0x90},{0xf8,0xf9,0x90,0x90,0x90,0x90}};
 for(unsigned i=0;i<4;++i)if(!run(carry[i],6,code,denied))return 7;
 RemoveVectoredExceptionHandler(handler);VirtualFree(code,0,MEM_RELEASE);VirtualFree(denied,0,MEM_RELEASE);printf("EXCEPTION_FLAGS_RESULT seen=%lu expected=520 mismatches=%lu\n",seen,bad);return seen==520&&!bad?0:6;}
