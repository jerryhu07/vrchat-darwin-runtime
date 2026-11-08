/* Resolve an export through the same read-only PE view used by the ELF caller. */
static unsigned read32(const void *p) {
  unsigned value;
  __builtin_memcpy(&value, p, sizeof(value));
  return value;
}
static unsigned short read16(const void *p) {
  unsigned short value;
  __builtin_memcpy(&value, p, sizeof(value));
  return value;
}
__attribute__((section(".text.pe_export")))
unsigned long long owned_pe_export(const unsigned char *image, const char *name) {
  const unsigned char *exports=image+read32(image+read32(image+60)+24+112);
  const unsigned char *functions=image+read32(exports+28);
  const unsigned char *names=image+read32(exports+32);
  const unsigned char *ordinals=image+read32(exports+36);
  unsigned count=read32(exports+24);
  for(unsigned i=0;i<count;++i) {
    const char *found=(const char*)image+read32(names+i*4);
    unsigned j=0;
    while(name[j] && name[j]==found[j])++j;
    if(!name[j] && !found[j])
      return (unsigned long long)(image+read32(functions+read16(ordinals+i*2)*4));
  }
  return 0;
}

__attribute__((section(".text.pe_notify")))
int owned_pe_notify(const unsigned long long *functions) {
  typedef int (__attribute__((ms_abi)) *Register)(unsigned, void *, void *, void **);
  typedef int (__attribute__((ms_abi)) *Unregister)(void *);
  void *cookie=0;
  int status=((Register)functions[0])(0,(void*)functions[2],0,&cookie);
  return status ? status : ((Unregister)functions[1])(cookie);
}
