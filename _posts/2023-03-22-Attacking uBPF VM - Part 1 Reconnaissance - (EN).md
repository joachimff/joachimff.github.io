---
title: Attacking uBPF VM - Part 1 Reconnaissance - (EN)
date: 2023-03-22 00:00:00 +0000
categories: [Fuzzing]
tags: [english, fuzzing, ubpf]
mermaid: true
---

The purpose of this series of articles is to present a case study on the research and exploitation of vulnerabilities in a real target: the uBPF library, an open-source implementation of an eBPF virtual machine. This library is used by Microsoft in its eBPF-for-Windows project.

To assist us, a specific fuzzer was developed in Rust. The bugs discovered are representative of common vulnerabilities found in C-written programs: invalid memory access, integer overflow, and undefined behavior. The process of exploiting these vulnerabilities is also detailed.

Although the target is relatively small (<3000 LoC), the methodology used to attack it is the same as for larger targets. This article aims to be informative and educational, and the developed fuzzer is open source and can be found on my GitHub.

Articles:
- [Attacking uBPF VM - Part 1 Reconnaissance - (EN)](https://joachimff.github.io/posts/Attacking-uBPF-VM-Part-1-Reconnaissance-(EN)/)
- [Attacking uBPF VM - Part 2 Writing the fuzzer - (EN)](https://joachimff.github.io/posts/Attacking-uBPF-VM-Part-2-Writing-the-fuzzer-(EN)/)
- [Attacking uBPF VM - Part 3 Bug Analysis - (EN)](https://joachimff.github.io/posts/Attacking-uBPF-VM-Part-3-Bug-Analysis-(EN)/)
Links:
- [Repo fuzzer](https://github.com/joachimff/eBPF-fuzzer)
- [Repo uBPF](https://github.com/iovisor/ubpf)

___This article has been translated with the help of AI.___

# Target
## eBPF VM 

The eBPF (Extended Berkeley Packet Filter) VM is a virtual machine that allows the execution of customized packet filtering programs on the Linux kernel. It was introduced in Linux kernel 3.18 and allows code to be executed in the kernel context without having to compile a specific module.

The nature of the eBPF VM makes it vulnerable to attacks. The programs executed within it are subjected to a verification process called the "**verifier**" to ensure that there are no bugs present in the code (infinite loops, unauthorized memory access, illegal instructions, etc.). The **verifier** uses a semantics-based verification approach to analyze the behavior of the program and ensure that the code does not contain any errors.

Once the code has been verified, it is compiled Just-In-Time (JIT) before being executed. The sandboxed environment ensures the isolation of the code in case of errors and prevents any unauthorized modification of the system.

## uBPF

The uBPF project is an initiative aimed at providing a userland eBPF execution environment under the Apache open-source license that can be reused in other projects. It offers two modes of eBPF program execution: in a virtual machine (VM) or in just-in-time (JIT) compilation followed by code execution.

This project does not provide a **verifier**, which has several implications for security:

-   In the case of execution in the virtual machine (VM), security checks are performed in real-time during program execution.
-   In the case of JIT compilation, no prior security checks are applied.

The project offers its own interpretation of the official spec (link), which is more concise. We will use it for the rest of the project.

The VM itself is a state machine with 11 64-bit registers + Program Counter (PC):

-   R0 is used to store the return value of a called function.
-   R1 to R5 are temporary registers used to store data during function execution.
-   R6 is a special register used for memory access and data manipulation.
-   R7 is reserved for system calls.
-   R8 and R9 are special registers used for accessing contextual data, such as file descriptors or IP addresses.
-   R10 is reserved for the stack pointer.

The instruction set is deliberately reduced and includes the following operation families:

-   ALU Instructions   
	* 64 bits   
	* 32 bits
-   Byteswap
-   Memory   
	* Load   
	* Store
-   Branch

**This library is used by Microsoft in its [ebpf-for-windows](https://github.com/microsoft/ebpf-for-windows) project.**

# Static Analysis

The analysis begins with a static inspection of the code. In the src/vm directory, three interesting files are identified:

-   **ubpf_loader.c** contains a single function **ubpf_load_elf**:
    -   Loads an ELF program (a binary executable file format used by Linux) into an eBPF VM.
    -   It seems interesting for our analysis because it involves many operations on pointers and memory, which can potentially cause bugs.
    -   It is considered out of scope for this series of articles, but I think it presents several security problems.
-   **ubpf_vm.c** contains all the functions used by the ubpf VM, among others: - **ubpf_create**: used to create a uBPF virtual machine. - **ubpf_load**: loads an eBPF program into the VM once it has been created, and the program is passed as a binary array. - **ubpf_exec**: executes the eBPF program loaded into the VM via the **ubpf_load** instruction, and at the end of the execution, the value of the r0 register is returned. - **ubpf_unload**: unloads an eBPF program from a VM, allowing the VM to be reused for another program.
    
-   **ubpf_jit.c**
    
    -   Two functions associated with the JIT compiler:
        -   **ubpf_translate**: compiles the code into machine code and stores it in the buffer passed as an argument.
        -   **ubpf_compile**: calls **ubpf_translate** and returns a pointer to a memory-allocated buffer containing the machine code via "calloc".
-   **test.c** contains an example of using the library for execution in a VM and JIT.

## How it works

After reading the documentation and sources, the library offers two methods for executing eBPF programs:   - Dynamically inside a VM via **ubpf_exec**, where the eBPF bytecode is not compiled into native x86 machine code.   - Compile the code into x86 instructions using ubpf_compile and ubpf_translate and then execute it.

In both cases, a VM must be created via **ubpf_create** and can be destroyed via **ubpf_destroy**.

This VM can then be used to load bytecode in two ways:   - **ubpf_load**: loads bytecode directly.   - **ubpf_load_elf**: loads an ELF file, with a minimal integrated parser.

Regarding the rest of the code, it can be noted that:

-   The same VM can be used for multiple eBPF programs, but it is necessary to call **ubpf_unload** before executing a new program. External functions are not unregistered.
-   The function **ubpf_toggle_bounds_check** can be used to set the bounds_check flag to 1, thus activating security checks for memory operations during VM execution (does not work for JIT compilation).
-   To protect against ROP attacks, instructions in memory can be XORed again with a secret value, which is set via the function **ubpf_set_pointer_secret**.
-   External functions called from eBPF code can be registered via the function **ubpf_register**.
-   It is possible to read and write to the registers of a VM using the functions **ubpf_set_registers** and **ubpf_get_registers**.

## Security check

The JIT compiler does not have any specific security measures, this part is normally handled by an external program called the verifier.

However, when the eBPF program is executed in a dynamic virtual machine, the **bounds_check** function is called before every memory access (store/load operations). If the address passed to these functions is outside the memory area of the VM's context or stack, an error is returned and the program execution is interrupted.

```c
static bool
bounds_check([...]
{
    if (!vm->bounds_check_enabled)
        return true;
    else if (mem && (addr >= mem && ((char*)addr + size) <= ((char*)mem + mem_len))) {
        /* Context access */
        return true;

    } else if (addr >= stack && ((char*)addr + size) <= ((char*)stack + UBPF_STACK_SIZE)) {
        /* Stack access */
        return true;
    } else {
        return false;
    }
}
```
___bounds_check () ubpf_vm.c___

This security check has a classic integer overflow bug, which will be quickly identified by our fuzzer.

Now that the reconnaissance step is complete, we can develop our fuzzer and start the dynamic analysis of the VM.

[Attacking uBPF VM - Part 2 Writing the fuzzer - (EN)](https://joachimff.github.io/posts/Attacking-uBPF-VM-Part-2-Writing-the-fuzzer-(EN)/)