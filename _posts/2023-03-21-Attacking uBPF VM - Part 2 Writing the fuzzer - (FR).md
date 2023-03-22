---
title: Attacking uBPF VM - Part 2 Writing the fuzzer - (FR)
date: 2023-03-21 00:00:00 +0000
categories: [Fuzzing]
tags: [français, fuzzing, ubpf]     # TAG names should always be lowercase
mermaid: true
---
# Attacking uBPF VM - Part 2 Writing the fuzzer - (FR)

Nous allons maintenant entreprendre une analyse dynamique de la VM pour identifier des bugs potentiels. Pour ce faire, nous allons développer un fuzzer sur mesure en Rust qui va générer un grand nombre de programmes eBPF et les exécuter dans la machine virtuelle fournie par uBPF. 

Étant donné la simplicité de la cible (moins de 2 000 lignes de code), le fuzzer sera simpliste, sans chercher à optimiser le nombre d'exécutions par seconde ou le code coverage.

Lien vers les articles:
- [Attacking uBPF VM - Part 1 Reconnaissance - (FR)](https://joachimff.github.io/posts/2023-03-21-Attacking-uBPF-VM-Part-1-Reconnaissance-(FR)/)
- [Attacking uBPF VM - Part 2 Writing the fuzzer - (FR)](https://joachimff.github.io/posts/2023-03-21-Attacking-uBPF-VM-Part-2-Writing-the-fuzzer-(FR)/)
- [Attacking uBPF VM - Part 3 Bug Analysis - (FR)](https://joachimff.github.io/posts/2023-03-21-Attacking-uBPF-VM-Part-3-Bug-Analysis-(FR)/)

This article is also available in english [here](https://joachimff.github.io/posts/Attacking-uBPF-VM-Part-2-Writing- the- fuzzer-(EN)/).

# Préparation de la cible
## Harness

La fonction ubpf_exec sera utilisé comme point d'entrée pour le fuzzer, car elle permet d'exécuter les programmes eBPF. Pourqu'elle  fonctionne correctement, il est nécessaire d'appeler les fonctions dans l'ordre suivant :

```mermaid
graph LR;
  ubpf_create-->ubpf_load-->ubpf_exec-->ubpf_destroy;
```

Les instructions générées par le fuzzer seront passées en argument de la fonction __ubpf_load__ et exécutées via __ubpf_exec__. Entre chaque exécution, la VM sera détruite et recréée pour éviter les effets de bord. Nous activerons le flag bounds_check_enabled (configuration par défaut) pour activer les controles de sécurité.

La librairie sera compilée en tant que bibliothèque externe en format .so, et notre fuzzer en Rust appellera directement les fonctions nécessaires.

## Modification et compilation de la bibliothéque

Afin de renforcer la sécurité de notre analyse, nous allons compiler la bibliothéque en activant l'AddressSanitizer (ASAN), un outil de detection d'erreur mémoire dans les programmes en C/C++, il permet d'identifier une multitude de vulnérabilités à l'executioon: buffer overflows, fuites de mémoire, comportements indéfinis, ect.

ASAN est pratique car il fait crasher le programme dès qu'une erreur est détéctée ce qui n'est pas forcément le cas dans une exécution classique où certains accès mémoire non maîtrisés ne provoquent pas nécessairement une erreur de segmentation, passant ainsi inaperçue.

Modifications apportées au Makefile:
```
LDLIBS := -lm -lubsan
CFLAGS += -fsanitize=address,undefined
LDFLAGS += -fsanitize=address,undefined
```

Pour lancer le fuzzer:
```
LD_PRELOAD=/usr/lib/gcc/x86_64-linux-gnu/9/libasan.so ./target/debug/j-fuzzer
```

En théorie, la machine virtuelle est censée détecter les boucles infinies dans le code. Cependant, lors des tests avec le fuzzer, j'ai remarqué que celui-ci se retrouvait bloqué plusieurs fois dans des boucles infinies. 

Pour éviter cela, la boucle principale d'exécution a été modifiée pour forcer l'arret de l'exécution après 100 000 instructions. De cette manière, le fuzzer peut continuer à générer et à tester des programmes sans être bloqué indéfiniment dans une boucle.

```c
---while (1) {

+++for(int i = 0; i < 100000; i++){
```

# Fuzzer  

## Utiliser une librairie en Rust  

Afin d'utiliser uBPF depuis notre fuzzer en Rust, la librairie est compilée en tant que bibliothèque (.so) et chargée au moment de l'exécution en utilisant la crate LoadLibrary. Les types de chaque fonction utilisée doivent être redéfinis en Rust ce qui peut être fastidieux.

Définition des prototypes des fonctions appelées en Rust:
```rust
type UbpfVm = c_void;
type UbpfCreateFn = unsafe extern fn() -> *mut UbpfVm;
type UbpfLoadFn = unsafe extern fn(*mut UbpfVm, *const c_char, u32, *mut *const c_char) -> i32;
type UbpfCompileFn = unsafe extern fn(*mut UbpfVm, *mut *const c_char) -> u64;
type UbpfDeleteFn = unsafe extern fn(*mut UbpfVm) -> ();
type UbpfExecFn = unsafe extern fn(*mut UbpfVm, *mut i8, u32, *mut u64) -> i32;
```

Appel des fonctions:
```rust
//import lib
let lib: &'static Library = Box::leak(Box::new(Library::new("../ubpf/vm/libubpf.so").unwrap()));

//import symbol
let ubpf_create_fn: Symbol<'static, UbpfCreateFn> = lib.get(b"ubpf_create").unwrap();

//call symbol
let vm: *mut UbpfVm = ubpf_create_fn();
```

## Générer des inputs valides

Le fuzzer doit produire des programmes eBPF aléatoires valides à exécuter dans la machine virtuelle. Pour ce faire, nous nous basons sur la documentation non officielle du format d'instruction eBPF du projet uBPF.

Les instructions eBPF sont encodées sur 64bits:: 
* 8 bit opcode
* 4 bit registre de destination (dst)
* 4 bit registre source (src)
* 16 bit offset
* 32 bit immediate (imm)

```
msb                                                        lsb
+------------------------+----------------+----+----+--------+
|immediate               |offset          |src |dst |opcode  |
+------------------------+----------------+----+----+--------+
```
*(Source: https://github.com/iovisor/bpf-docs/blob/master/eBPF.md)

Afin de manipuler ces instructions en Rust, nous avons défini les deux types suivants :
```rust
struct EbpfInstr{
  opcode: u8,
  dst: u8,
  src: u8,
  offset: u16,
  imm: i32
}

struct EbpfBytecode([c_char; 8]);
```

Pour générer une instruction, nous procédons comme suit :
-   Selection d'un opcode de manière aléatoire dans la liste des opcodes existants.
-   Choix aléatoire des registres de destination et source.
-   Choix aléatoire de la valeur immédiate et de l'offset, sauf dans deux cas particuliers :
    -   Pour les instructions "byteswap", nous limitons les valeurs immédiates possibles à 16, 32 ou 64.
    -   Pour les instructions "branch", nous vérifions que la valeur offset additionnée au PC se situe dans la plage d'adresses de mémoire du programme, c'est-à-dire entre 0 et le nombre d'instructions du programme.

Code simplifié pour générer une instruction :
```rust
fn generate_random_instr (i: i32) -> EbpfInstr{   
	let opcode = OPCODE[rand::thread_rng().gen_range(0..OPCODE.len())];
	let mut offset = 0;
	let mut imm = 0;
	
	if is_branch{
	  offset = rand::thread_rng().gen_range(-i .. (((NBR_INSTR + 1) as i32) - i - 1)) as u16;
	}
	else{
	  offset = rand::thread_rng().gen_range(0..0xFF_FF);
	}
	
	if is_bit_swap{
	  let values = [16, 32, 64];
	  imm = values[rand::thread_rng().gen_range(0..3)];
	}
	else{
	  imm = rand::thread_rng().gen::<i32>();
	}
	
	EbpfInstr{
	  opcode: opcode,
	  dst: rand::thread_rng().gen_range(0..10),
	  src: rand::thread_rng().gen_range(0..10),
	  offset: offset,
	  imm: imm
	}
}
```

## Executer la vm

Une fois les fonctions chargées dans le programme, la boucle principale du fuzzer est appelée:
-   Une nouvelle machine virtuelle eBPF est créée.
-   Un programme comportant un nombre spécifié d'instructions (32 durant les tests) est généré.
-   Le programme est chargé dans la machine virtuelle.
-   Un buffer pour le stack est alloué.
-   Le programme est exécuté dans la machine virtuelle.
-   La machine virtuelle est détruite.

Voici à quoi ressemble le code de la boucle principale :
```rust
loop{
	//création VM eBPF
	vm: *mut UbpfVm = ubpf_create_fn();
	
	//génération programme eBPF aléatoire
	let mut bytecode: [EbpfBytecode; NBR_INSTR + 1] = [EbpfBytecode::default(); NBR_INSTR + 1];
	
	for j in 0..NBR_INSTR as i32{
	  let instr = EbpfInstr::generate_random_instr(j);
	  let instr_byte = EbpfBytecode::from(instr);
	  
	  bytecode[j as usize] = instr_byte;
	}
	//ajoute instruction exit en fin de programe
	bytecode[NBR_INSTR] = EbpfBytecode::from(EbpfInstr::new(0x95, 0x00, 0x00, 0x0000, 0x00000000));
	
	//charge le programme dans la vm
	ubpf_load_fn(vm, bytecode.as_ptr() as *const c_char, 8 * (NBR_INSTR + 1) as u32, &mut errmsg_ptr)
	
	//allocation pointeur pour récupérer la valeur de retour
	let ret_val_ptr: *mut u64 = std::mem::MaybeUninit::<u64>::uninit().as_mut_ptr();
	
	//allocation stack
	let mut buffer: Vec<u8> = vec![0; STACK_SIZE];
	let buf_ptr = buffer.as_mut_ptr() as *mut c_char;
	
	//execute le programme
	ubpf_exec_fn(vm, buf_ptr, STACK_SIZE, ret_val_ptr);
	
	//destruction vm
	ubpf_destroy_fn(vm);
	[...]
}
```

Le fuzzer est maintenant fonctionnel, vous pouvez retrouver le code complet sur mon #TODO [github](). 

Les tests sont réalisés dans une VM Ubuntu dans WSL sur un PC portable, les performances du fuzzer sont basses  (4000 exec/s), cependant ce sera suffisant pour trouver des bugs interessants puisqu'après seulement 5 minutes d'execution 2 bugs ont été identifiés.

[=>Partie 3: Writing the fuzzer](https://joachimff.github.io/posts/2023-03-21-Attacking-uBPF-VM-Part-3-Bug-Analysis-(FR)/)

