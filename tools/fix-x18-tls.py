#!/usr/bin/env python3
# VKMT: rewrite x18/w18 TEB references to x28/w28 in aarch64 PE
# binaries. LLVM's Windows-aarch64 TLS lowering hardcodes x18 (TEB.TlsSlots);
# VKMT keeps the TEB in x28. Safe because all our PE code is built with
# -ffixed-x18, so no legitimate x18 allocation remains in .text.
import os, re, shutil, subprocess, sys, tempfile
from pathlib import Path

BIN = os.environ.get("LLVM_BIN")
if not BIN:
    objdump = shutil.which("llvm-objdump")
    if not objdump:
        raise SystemExit("llvm-objdump is required on PATH")
    BIN = str(Path(objdump).parent)

def patch(path):
    out = subprocess.run([f"{BIN}/llvm-objdump", "-d", "--no-show-raw-insn", path],
                         capture_output=True, text=True, check=True).stdout
    sites = [(int(m.group(1), 16), m.group(2).split('//')[0].strip()) for line in out.splitlines()
             if (m := re.match(r"\s*([0-9a-f]+):\s+(.+)", line)) and re.search(r'\b[wx]18\b', m.group(2))]
    if not sites:
        print(f"{path}: no x18 operands found")
        return

    # NtCurrentTeb also becomes ADD, CMP and register stores. Let LLVM encode
    # both forms instead of assuming that every reference is a memory base.
    instructions = []
    for _, instruction in sites:
        instructions += [instruction, re.sub(r'\b([wx])18\b', r'\g<1>28', instruction)]
    with tempfile.TemporaryDirectory() as directory:
        obj, binary = Path(directory) / 'teb.o', Path(directory) / 'teb.bin'
        subprocess.run([f'{BIN}/clang', '--target=aarch64-none-elf', '-x', 'assembler', '-c', '-', '-o', str(obj)],
                       input='.text\n' + '\n'.join(instructions) + '\n', text=True, check=True)
        subprocess.run([f'{BIN}/llvm-objcopy', '--only-section=.text', '-O', 'binary', str(obj), str(binary)], check=True)
        encoded = binary.read_bytes()
    if len(encoded) != 4 * len(instructions):
        raise ValueError('Expected one complete AArch64 instruction per TEB reference')
    encodings = [encoded[i:i + 4] for i in range(0, len(encoded), 4)]

    hdr = subprocess.run([f"{BIN}/llvm-readobj", "--sections", "--file-headers", path],
                         capture_output=True, text=True, check=True).stdout
    image_base = int(re.search(r"ImageBase: (0x[0-9a-fA-F]+)", hdr).group(1), 16)
    secs = []  # (vma, fileoff, size)
    for m in re.finditer(r"VirtualAddress: (0x[0-9a-f]+)\n(?:.*\n)*?\s+RawDataSize: (\d+)\n\s+PointerToRawData: (0x[0-9a-f]+)", hdr):
        rva, size, off = int(m.group(1), 16), int(m.group(2)), int(m.group(3), 16)
        secs.append((image_base + rva, off, size))

    data = bytearray(open(path, "rb").read())
    patched = 0
    for index, (va, instruction) in enumerate(sites):
        for vma, off, size in secs:
            if vma <= va < vma + size:
                fo = off + (va - vma)
                if data[fo:fo + 4] != encodings[index * 2]:
                    raise ValueError(f'Instruction did not round-trip at {va:#x}: {instruction}')
                data[fo:fo + 4] = encodings[index * 2 + 1]
                patched += 1
                break
        else:
            raise ValueError(f"No section for address {va:#x}")
    open(path, "wb").write(data)
    print(f"{path}: patched {patched}/{len(sites)} x18->x28 sites")

for p in sys.argv[1:]:
    patch(p)
