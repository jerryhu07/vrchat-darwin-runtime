// Shared ABI from the accepted v1571 native Wine bridge.
#pragma once
#include <atomic>
#include <cstdint>

namespace NativeTrace {
struct LinuxRegisters {
  uint64_t r15,r14,r13,r12,rbp,rbx,r11,r10,r9,r8,rax,rcx,rdx,rsi,rdi,orig_rax,rip,cs,eflags,rsp,ss,fs_base,gs_base,ds,es,fs,gs;
};
static_assert(sizeof(LinuxRegisters)==216);
struct RootAliasMetadata { uint64_t guest,length,host,span,protection,offset; };
struct TraceState {
  uint64_t magic=0x464c495452414331ULL;
  int relay_fd=-1;
  std::atomic<uint64_t> options{0};
  std::atomic<bool> traced{false},syscalls{false},syscall_stop{false};
  bool stopped=false; // Parent's private bookkeeping after a real waitpid stop.
  LinuxRegisters registers{};
  alignas(16) unsigned char floating[512]{};
  std::atomic<bool> floating_valid{false};
  std::atomic<bool> alignment_routing{false},probe_bus{false},registers_valid{false};
  std::atomic<int> pending_signal{0},delivery_signal{0},fault_code{0};
  std::atomic<uint64_t> frame{0},fault_frame{0},fault_pc{0},fault_address{0},alignments{0};
  std::atomic<uint32_t> fault_esr{0};
  std::atomic<uint32_t> fault_guest_prot{UINT32_MAX},fault_wine_prot{0},fault_wine_type{0};
  std::atomic<uint64_t> fault_allocation{0};
  std::atomic<uint64_t> cpu_area{0};
  std::atomic<uint64_t> code_writes{0};
  std::atomic<bool> exec_pending{false},exec_completed{false};
  std::atomic<uint64_t> exec_old_tid{0};
  uint32_t last_stop_status=0;
  std::atomic<bool> deferred_exec{false},frontend_ready{false};
  std::atomic<unsigned> elf_count{0};
  char guest_program[512]{};
  struct Region {uint64_t start,end,offset;uint32_t flags;char name[512];} elf[64]{};
  RootAliasMetadata aliases[4]{};
  std::atomic<unsigned> alias_count{0};
  std::atomic<bool> root_owner{false};
  std::atomic<uint64_t> smc_base{0};
  std::atomic<uint64_t> smc_pages[4096]{}; // One bit per native page in the real 4 GiB ELF arena.
  std::atomic<uint64_t> dirty_begin{UINT64_MAX},dirty_end{0};
  std::atomic<bool> root_trap_stop{false};
  std::atomic<int> root_trap_code{0};
  std::atomic<int> root_signal{0};
  std::atomic<int> root_delivery_signal{0};
  std::atomic<uint64_t> root_siginfo_address{0};
  std::atomic<bool> root_siginfo_address_valid{false};
};
} // namespace NativeTrace
