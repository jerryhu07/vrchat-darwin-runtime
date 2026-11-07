#include "memory-owner-peer.h"
#include <cstring>
#include <cstdio>
#include <dlfcn.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <mach-o/dyld.h>
#include <thread>
using RootCall=int32_t(*)(uint64_t,const uint64_t*,uint64_t*);
static RootCall call;
static uint64_t syscall_entry,allocation,code,alias_code,libc_base;
static int32_t initialize(void *opaque) {
  auto start=(int32_t(*)(uint64_t*))dlsym(RTLD_DEFAULT,"fli_start_glibc");
  auto map=(int32_t(*)(const uint64_t*,uint64_t*,int32_t*))dlsym(RTLD_DEFAULT,"fli_root_mmap");
  call=(RootCall)dlsym(RTLD_DEFAULT,"fli_root_guest_call_control");
  if(!start||!map||!call)return -38;
  uint64_t state[4]{};if(start(state))return -5;
  for(uint64_t link=state[0],i=0;link && i<32;++i) {
    uint64_t row[5]{};char name[1024]{};mach_vm_size_t count=0;
    if(mach_vm_read_overwrite(mach_task_self(),link,sizeof(row),(mach_vm_address_t)row,&count)!=KERN_SUCCESS)return -14;
    if(row[1] && mach_vm_read_overwrite(mach_task_self(),row[1],sizeof(name)-1,(mach_vm_address_t)name,&count)==KERN_SUCCESS && strstr(name,"/libc.so.6")) {
      libc_base=row[0];syscall_entry=row[0]+FLI_TEST_SYSCALL_RVA;break;
    }
    link=row[3];
  }
  if(!syscall_entry)return -38;
  uint64_t args[6]={0,65536,3,0x22,UINT64_MAX,0};int32_t error=0;
  if(map(args,&allocation,&error)||error||allocation==UINT64_MAX)return -12;
  code=(allocation+16383)&~uint64_t(16383);
  const unsigned char writer[]={0x89,0x37,0x31,0xc0,0xc3};
  if(mach_vm_write(mach_task_self(),code+16384,(vm_offset_t)writer,sizeof(writer))!=KERN_SUCCESS)return -14;
  *(FliMemoryPeer*)opaque={code,16384,3,0};return 0;
}
static int32_t query(void *opaque) {
  auto &r=*(FliMemoryPeer*)opaque;
  auto read=(int32_t(*)(uint64_t,uint64_t*))dlsym(RTLD_DEFAULT,"fli_root_guest_query_memory");
  uint64_t out[4]{};r.result=read?read(r.address,out):-38;
  if(!r.result){r.protection=out[3];r.length=out[1];}return 0;
}
static int32_t execute(void *opaque) {
  uint64_t args[6]{},result=0;const int status=call(code,args,&result);
  ((FliMemoryPeer*)opaque)->result=status?status:int64_t(result);return 0;
}
static int32_t cleanup(void *) {
  if(alias_code) {
    uint64_t release[6]={11,alias_code,4096,0,0,0},ignored=0;
    if(call(syscall_entry,release,&ignored)||ignored)return -5;
    alias_code=0;
  }
  uint64_t args[6]={11,allocation,65536,0,0,0},result=0;
  return call(syscall_entry,args,&result)?-5:int32_t(result);
}
static int32_t write_from_root(void *opaque) {
  uint64_t args[6]={code+1,9876,0,0,0,0},result=0;
  const int status=call(code+16384,args,&result);
  ((FliMemoryPeer*)opaque)->result=status?status:int64_t(result);return 0;
}
static int32_t map_alias(void *opaque) {
  auto &r=*(FliMemoryPeer*)opaque;
  auto map=(int32_t(*)(const uint64_t*,uint64_t*,int32_t*))dlsym(RTLD_DEFAULT,"fli_root_mmap");
  const uint64_t address=code+32768;
  uint64_t args[6]={address,4096,5,0x11,r.protection,0},result=0;int32_t error=0;
  if(!map || map(args,&result,&error) || error || result!=address)return -12;
  alias_code=address;r={address,4096,5,0};return 0;
}
static int32_t execute_alias(void *opaque) {
  uint64_t args[6]{},result=0;const int status=call(alias_code,args,&result);
  ((FliMemoryPeer*)opaque)->result=status?status:int64_t(result);return 0;
}
static int32_t read_root_clock(void *opaque) {
  uint64_t args[6]={228,1,code+4096,0,0,0},result=0;
  const int status=call(syscall_entry,args,&result);
  uint64_t values[2]{};mach_vm_size_t copied=0;
  auto &out=*(FliMemoryPeer*)opaque;
  if(status || result || mach_vm_read_overwrite(mach_task_self(),code+4096,sizeof(values),
      reinterpret_cast<mach_vm_address_t>(values),&copied)!=KERN_SUCCESS || copied!=sizeof(values)) {
    out.result=-5;return 0;
  }
  out.result=int64_t(values[0]*1000000000ULL+values[1]);return 0;
}
static int32_t kernel_file_cursor(void *opaque) {
  auto &r=*(FliMemoryPeer*)opaque;const int fd=int(r.address);
  if(r.length==0)r.result=lseek(fd,0,SEEK_CUR);
  else if(r.length==1) {
    int alias=dup(fd);unsigned char value=0;
    r.result=alias<0?-1:read(alias,&value,1)==1?value:-1;
    if(alias>=0)close(alias);
  } else if(r.length==2) {
    pid_t child=fork();
    if(!child){unsigned char value=0;_exit(read(fd,&value,1)==1?value:255);}
    int status=0;r.result=child>0 && waitpid(child,&status,0)==child && WIFEXITED(status)?WEXITSTATUS(status):-1;
  } else r.result=-22;
  return 0;
}
static int32_t wine_thread_state(void *opaque) {
  auto &r=*(FliMemoryPeer*)opaque;
  auto invoke=(int32_t(*)(uint64_t,const uint64_t*,uint64_t,uint64_t*))
      dlsym(RTLD_DEFAULT,"fli_root_guest_call_wine_control");
  uint64_t args[6]={r.address,0,0,0,0,0},result=0;
  const int status=invoke?invoke(code,args,r.protection,&result):-38;
  r.result=status?status:int64_t(result);return 0;
}
static int32_t mutex_function(void *opaque) {
  auto &r=*(FliMemoryPeer*)opaque;
  const uint64_t offsets[]={FLI_TEST_MUTEX_RVA_0,FLI_TEST_MUTEX_RVA_1,FLI_TEST_MUTEX_RVA_2,
    FLI_TEST_MUTEX_RVA_3,FLI_TEST_MUTEX_RVA_4,FLI_TEST_MUTEX_RVA_5};
  r.result=r.length<6?int64_t(libc_base+offsets[r.length]):-22;return 0;
}
static int32_t provider_count(void *opaque) {
  unsigned count=0;
  for(uint32_t i=0;i<_dyld_image_count();++i) {
    const char *name=_dyld_get_image_name(i);
    if(name && strstr(name,"libfli_linux_syscall_bridge")) {
      ++count;printf("OWNED_PROVIDER_IMAGE %s\n",name);
    }
  }
  ((FliMemoryPeer*)opaque)->result=count;return 0;
}
static int32_t atomic_operation(void *opaque) {
  auto &r=*(FliMemoryPeer*)opaque;
  uint64_t args[6]={r.address,r.length,r.protection,0,0,0},result=0;
  const int status=call(code,args,&result);
  r.result=status?status:int64_t(result);return 0;
}
static std::thread atomic_worker;
static uint64_t atomic_result;
static int atomic_status;
static int32_t atomic_start(void *opaque) {
  const auto r=*(FliMemoryPeer*)opaque;
  if(atomic_worker.joinable())return -16;
  atomic_worker=std::thread([r] {
    uint64_t args[6]={r.address,r.length,r.protection,0,0,0};
    atomic_status=call(code,args,&atomic_result);
  });
  return 0;
}
static int32_t atomic_join(void *opaque) {
  if(!atomic_worker.joinable())return -22;
  atomic_worker.join();
  ((FliMemoryPeer*)opaque)->result=atomic_status?atomic_status:int64_t(atomic_result);
  return 0;
}
static int32_t root_sleep(void *opaque) {
  auto &r=*(FliMemoryPeer*)opaque;
  uint64_t request[2]={r.address,r.length},args[6]{},result=0;
  memcpy(reinterpret_cast<void*>(code+8192),request,sizeof(request));
  if(r.protection==35){args[0]=35;args[1]=code+8192;}
  else {args[0]=230;args[1]=1;args[2]=1;args[3]=code+8192;}
  const int status=call(syscall_entry,args,&result);r.result=status?status:int64_t(result);return 0;
}
static int32_t root_cwd(void* opaque) {
  auto& r=*static_cast<FliMemoryPeer*>(opaque);uint64_t result=0;
  const uint64_t args[6]={79,r.protection?1:code+4096,r.length,0,0,0};
  const int status=call(syscall_entry,args,&result);
  r.result=status?status:int64_t(result);
  if(!status && result==UINT64_MAX) {
    uint64_t noargs[6]{},pointer=0;
    const int queried=call(libc_base+FLI_TEST_ERRNO_RVA,noargs,&pointer);
    int error=0;mach_vm_size_t copied=0;
    if(queried || !pointer || mach_vm_read_overwrite(mach_task_self(),pointer,sizeof(error),reinterpret_cast<mach_vm_address_t>(&error),&copied)!=KERN_SUCCESS || copied!=sizeof(error))r.result=-5;
    else r.result=-error;
  }
  return 0;
}
static int32_t host_cwd(void* opaque) {
  auto& r=*static_cast<FliMemoryPeer*>(opaque);
  char* result=getcwd(reinterpret_cast<char*>(code+12288),4096);
  r.result=result?int64_t(strlen(result)+1):-errno;return 0;
}
static int32_t linux_device_number(void* opaque) {
  auto& r=*static_cast<FliMemoryPeer*>(opaque);const uint64_t args[6]={r.address,0,0,0,0,0};uint64_t major=0,minor=0;
  const int a=call(libc_base+FLI_TEST_DEV_MAJOR_RVA,args,&major),b=call(libc_base+FLI_TEST_DEV_MINOR_RVA,args,&minor);
  r.result=a?a:b?b:int64_t((major<<32)|minor);return 0;
}
static int32_t libc_fork_address(void *opaque) {auto& r=*(FliMemoryPeer*)opaque;r.result=libc_base+FLI_TEST_FORK_RVA;r.length=libc_base+FLI_TEST_RAISE_RVA;void* p=mmap(nullptr,4096,PROT_READ|PROT_WRITE,MAP_SHARED|MAP_ANON,-1,0);if(p==MAP_FAILED)return -errno;r.address=(uint64_t)p;return 0;}
static int32_t root_program_break(void *opaque) {auto& r=*(FliMemoryPeer*)opaque;uint64_t args[6]={12,r.length,0,0,0,0},result=0;const int status=call(syscall_entry,args,&result);r.result=status?status:int64_t(result);return 0;}
static int32_t root_syscall_control(void* opaque) {
 auto& r=*(FliMemoryPeer*)opaque;uint64_t args[6]{};memcpy(args,(void*)r.address,sizeof(args));uint64_t result=0;const int status=call(syscall_entry,args,&result);r.result=status?status:int64_t(result);
 if(!status && result==UINT64_MAX){uint64_t noargs[6]{},pointer=0;if(call(libc_base+FLI_TEST_ERRNO_RVA,noargs,&pointer)||!pointer)r.result=-5;else {int value=0;mach_vm_size_t copied=0;if(mach_vm_read_overwrite(mach_task_self(),pointer,4,(mach_vm_address_t)&value,&copied)||copied!=4)r.result=-5;else r.result=-value;}}
 return 0;
}
static int32_t libc_pthread_addresses(void* opaque){auto& r=*static_cast<FliMemoryPeer*>(opaque);r.address=libc_base+FLI_TEST_PTHREAD_CREATE_RVA;r.length=libc_base+FLI_TEST_PTHREAD_JOIN_RVA;return 0;}
static int32_t root_syscall_wine_control(void* opaque) {
 auto& r=*static_cast<FliMemoryPeer*>(opaque);uint64_t args[6]{},result=0;memcpy(args,(void*)r.address,sizeof(args));
 auto invoke=(int32_t(*)(uint64_t,const uint64_t*,uint64_t,uint64_t*))dlsym(RTLD_DEFAULT,"fli_root_guest_call_wine_control");
 const int status=invoke?invoke(syscall_entry,args,r.protection,&result):-38;r.result=status?status:int64_t(result);return 0;
}
extern "C" __attribute__((visibility("default")))
int32_t (*const __wine_unix_call_funcs[])(void*)={initialize,query,execute,cleanup,write_from_root,map_alias,execute_alias,read_root_clock,kernel_file_cursor,wine_thread_state,mutex_function,provider_count,atomic_operation,atomic_start,atomic_join,root_sleep,root_cwd,host_cwd,linux_device_number,libc_fork_address,root_program_break,root_syscall_control,libc_pthread_addresses,root_syscall_wine_control};
