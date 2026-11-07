#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

uint64_t metadata_relaxed_load(const uint64_t *);
uint64_t metadata_ordered_load(const uint64_t *);
uint64_t metadata_unknown_load(const uint64_t *);
uint64_t metadata_nop(const uint64_t *);
void metadata_ordered_store(uint64_t *, uint64_t);
void metadata_unknown_store(uint64_t *, uint64_t);
void metadata_vector(const void *, void *);
void metadata_relaxed_store(uint64_t *, uint64_t);
void metadata_relaxed_vector(const void *, void *);
void metadata_unknown_vector(const void *, void *);
DWORD WINAPI metadata_producer(void *);
DWORD WINAPI metadata_consumer(void *);

// Owned assembly with standard PE volatile metadata. No vendor binary is edited.
// Include a metadata range with no access entries at its end, plus unknown code
// immediately outside that range. The latter must retain conservative ordering.
__asm__(
  ".section .text$metadata,\"xr\"\n.p2align 4\nmetadata_begin:\n"
  ".globl metadata_relaxed_load\nmetadata_relaxed_load:\nmovq (%rcx),%rax\nret\n"
  ".globl metadata_ordered_load\nmetadata_ordered_load:\nordered_load:\nmovq (%rcx),%rax\nret\n"
  ".globl metadata_ordered_store\nmetadata_ordered_store:\nordered_store:\nmovq %rdx,(%rcx)\nret\n"
  ".globl metadata_nop\nmetadata_nop:\nmovq (%rcx),%rax\nordered_nop:\nnop\n"
  "ordered_nop_short:\n.byte 0x66,0x90\nordered_nop_modrm:\n.byte 0x0f,0x1f,0x00\n"
  "ordered_nop_lea:\nleaq 0(%rcx),%rcx\nret\n"
  ".globl metadata_vector\nmetadata_vector:\nordered_vector_load:\nmovdqu (%rcx),%xmm0\n"
  "ordered_vector_store:\nmovdqu %xmm0,(%rdx)\nret\n"
  ".globl metadata_producer\nmetadata_producer:\nmovl $1,%r8d\nproducer_loop:\n"
  "leaq -1(%r8),%rdx\nproducer_ack_load:\nmovq 16(%rcx),%rax\ncmpq %rdx,%rax\njne producer_loop\n"
  "movq %r8,(%rcx)\nproducer_publish:\nmovq %r8,8(%rcx)\nincq %r8\ncmpq $10001,%r8\njne producer_loop\nxorl %eax,%eax\nret\n"
  ".globl metadata_consumer\nmetadata_consumer:\nmovl $1,%r8d\nconsumer_loop:\n"
  "consumer_published_load:\nmovq 8(%rcx),%rax\ncmpq %r8,%rax\njne consumer_loop\n"
  "movq (%rcx),%rax\ncmpq %r8,%rax\nje consumer_good\nincq 24(%rcx)\nconsumer_good:\n"
  "consumer_ack_store:\nmovq %r8,16(%rcx)\nincq %r8\ncmpq $10001,%r8\njne consumer_loop\nxorl %eax,%eax\nret\n"
  ".globl metadata_relaxed_store\nmetadata_relaxed_store:\nmovq %rdx,(%rcx)\nret\n"
  ".globl metadata_relaxed_vector\nmetadata_relaxed_vector:\nmovdqu (%rcx),%xmm0\nmovdqu %xmm0,(%rdx)\nret\n"
  ".globl metadata_empty_tail\nmetadata_empty_tail:\nmovq (%rcx),%rax\nret\nmetadata_end:\n"
  ".globl metadata_unknown_load\nmetadata_unknown_load:\nmovq (%rcx),%rax\nret\n"
  ".globl metadata_unknown_store\nmetadata_unknown_store:\nmovq %rdx,(%rcx)\nret\n"
  ".globl metadata_unknown_vector\nmetadata_unknown_vector:\nmovdqu (%rcx),%xmm0\nmovdqu %xmm0,(%rdx)\nret\n"
  ".section .rdata$metadata,\"dr\"\n.p2align 3\n"
  ".globl _load_config_used\n_load_config_used:\n.long 0x138\n.zero 0xfc\n.quad volatile_header\n.zero 0x30\n"
  "volatile_header:\n.long 24,1\n.rva volatile_accesses\n.long volatile_accesses_end-volatile_accesses\n"
  ".rva volatile_ranges\n.long volatile_ranges_end-volatile_ranges\n"
  "volatile_accesses:\n.rva ordered_load,ordered_store,ordered_nop,ordered_vector_load,ordered_vector_store\n"
  ".rva producer_ack_load,producer_publish,consumer_published_load,consumer_ack_store\n"
  ".rva ordered_nop_short,ordered_nop_modrm,ordered_nop_lea\nvolatile_accesses_end:\n"
  "volatile_ranges:\n.rva metadata_begin\n.long metadata_end-metadata_begin\nvolatile_ranges_end:\n.text\n");

extern IMAGE_DOS_HEADER __ImageBase;
extern uint64_t metadata_empty_tail(const uint64_t *);

int main(int argc, char **argv) {
  setvbuf(stdout, NULL, _IONBF, 0);
  const unsigned char *image = (const unsigned char *)&__ImageBase;
  const IMAGE_NT_HEADERS64 *nt = (const void *)(image + __ImageBase.e_lfanew);
  const unsigned char *config = image + nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress;
  const uint32_t *metadata = *(const uint32_t *const *)(config + 0x100);
  if (!metadata || metadata[0] != 24 || metadata[3] != 12 * 4 || metadata[5] != 8) return 2;
  uint64_t value = UINT64_C(0x123456789abcdef0), copy = 0;
  unsigned bad = 0;
  bad += metadata_relaxed_load(&value) != value;
  bad += metadata_ordered_load(&value) != value;
  bad += metadata_unknown_load(&value) != value;
  bad += metadata_empty_tail(&value) != value;
  bad += metadata_nop(&value) != value;
  metadata_ordered_store(&copy, value); bad += copy != value;
  metadata_unknown_store(&copy, value + 1); bad += copy != value + 1;
  uint64_t input[2] = {value, value + 1}, output[2] = {0};
  metadata_vector(input, output); bad += output[0] != input[0] || output[1] != input[1];
  metadata_relaxed_store(&copy, value); bad += copy != value;
  output[0] = output[1] = 0;
  metadata_relaxed_vector(input, output); bad += output[0] != input[0] || output[1] != input[1];
  output[0] = output[1] = 0;
  metadata_unknown_vector(input, output); bad += output[0] != input[0] || output[1] != input[1];
  uint64_t shared[4] = {0};
  HANDLE threads[2] = {CreateThread(NULL, 0, metadata_producer, shared, 0, NULL),
                       CreateThread(NULL, 0, metadata_consumer, shared, 0, NULL)};
  if (!threads[0] || !threads[1] || WaitForMultipleObjects(2, threads, TRUE, 10000) != WAIT_OBJECT_0) return 3;
  for (unsigned i = 0; i < 2; ++i) {
    DWORD code = 1;
    bad += !GetExitCodeThread(threads[i], &code) || code;
    CloseHandle(threads[i]);
  }
  bad += shared[3] != 0 || shared[1] != 10000 || shared[2] != 10000;
  printf("VOLATILE_METADATA_RESULT accesses=12 rounds=10000 failures=%u\n", bad);
  if (argc > 1) {
    unsigned hold = strtoul(argv[1], NULL, 10);
    if (hold > 30000) return 4;
    printf("VOLATILE_PROVIDER base=%llx\n", (unsigned long long)(uintptr_t)GetModuleHandleW(L"xtajit64.dll"));
    Sleep(hold);
  }
  return bad ? 1 : 0;
}
