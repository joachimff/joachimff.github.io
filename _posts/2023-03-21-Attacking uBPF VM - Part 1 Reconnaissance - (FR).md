---
title: Attacking uBPF VM - Part 1 Reconnaissance - (FR)
date: 2023-03-21 00:00:00 +0000
categories: [Fuzzing]
tags: [français, fuzzing, ubpf]
mermaid: true
---
# Attacking uBPF VM - Part 1 Reconnaissance - (FR)

Cette série d'articles à pour but de présenter une étude de cas sur la recherche et l'exploitation de vulnérabilités d'une cible réelle: la librairie uBPF, une implémentation open-source d'une machine virtuelle eBPF. __Cette librairie est utilisée par Microsoft dans son projet eBPF-for-Windows__.

Pour nous nous aider un fuzzer spécifique a été développé en Rust. Les bugs découverts sont représentatifs des vulnérabilités courantes que l'on retrouve dans les programmes écrits en C: invalid memory access, integer overflow, undefined behavior. Le processus d'exploitation de ces vulnérabilités est également détaillé.

Bien que la cible soit relativement petite (<3000 LoC), la méthodologie employée pour l'attaquer est la même que pour des cibles de plus grande envergure.  Cet article se veut informatif et éducatif, le fuzzer développé est open source et peut être retrouvé sur mon github.

Lien vers les articles:
- [Attacking uBPF VM - Part 1 Reconnaissance - (FR)](https://joachimff.github.io/posts/Attacking-uBPF-VM-Part-1-Reconnaissance-(FR)/)
- [Attacking uBPF VM - Part 2 Writing the fuzzer - (FR)](https://joachimff.github.io/posts/Attacking-uBPF-VM-Part-2-Writing-the-fuzzer-(FR)/)
- [Attacking uBPF VM - Part 3 Bug Analysis - (FR)](https://joachimff.github.io/posts/Attacking-uBPF-VM-Part-3-Bug-Analysis-(FR)/)

Links:
- [Repo fuzzer](https://github.com/joachimff/eBPF-fuzzer)
- [Repo uBPF](https://github.com/iovisor/ubpf)

This article is also available in english  [here](https://joachimff.github.io/posts/Attacking-uBPF-VM-Part-1-Reconnaissance-(EN)/).


# Comprendre la cible
## Machine virtuelle eBPF 

La VM eBPF (Extended Berkeley Packet Filter) est une machine virtuelle qui permet l'exécution de programmes de filtrage de paquets personnalisés sur le noyau Linux. Elle a été introduite dans le noyau Linux 3.18 elle permet d'executer du code dans le contexte du kernel sans avoir a compiler de module spécifique.

La nature de la VM eBPF la rend vulnérable aux attaques. Les programmes qui y sont exécutés sont soumis à un processus de vérification appelé "**verifier**" pour s'assurer qu'aucun bug n'est présent dans le code ( boucles infinies, accès mémoire non autorisés, instructions illégales, ect...). Le **verifier** utilise une approche de vérification basée sur une sémantique pour analyser le comportement du programme et garantir que le code ne contient pas d'erreurs.

Une fois que le code a été vérifié, il est compilé en Just-In-Time (JIT) avant d'être executé. L'environnement sandboxé assure l'isolation du code en cas d'erreur et empêche toute modification non autorisée du système.

## uBPF

Le projet uBPF est une initiative qui vise à offrir un environnement d'exécution eBPF userland sous licence libre Apache pouvant être réutilisé dans d'autres projets. Il propose deux modes d'exécutiondes programmes eBPF : dans une machine virtuelle (VM) ou en compilation JIT suivie de l'exécution du code. 

Ce projet de propose pas de __verifier__, ce qui à plusieurs implications en terme de sécurité: 
- Dans le cas d'une exécution dans la machine virtuelle (VM), les contrôles de sécurité sont effectués en temps réel lors de l'exécution du programme.  
- Dans le cas d'une compilation JIT aucun contrôle de sécurité préalable n'est appliqué. 

Le projet propose sa propre interprétation de la spec officielle (lien), plus concise nous allons nous baser dessus pour la suite du projet.

La VM en elle même est une machine a état de 11 registres de 64 bits + Program Counter (PC):
-   R0 est utilisé pour stocker la valeur de retour d'une fonction appelée.
-   R1 à R5 sont des registres temporaires utilisés pour stocker des données pendant l'exécution d'une fonction.
-   R6 est un registre spécial utilisé pour l'accès à la mémoire et la manipulation des données.
-   R7 est réservé pour les appels système.
-   R8 et R9 sont des registres spéciaux utilisés pour l'accès aux données contextuelles, tels que les descripteurs de fichiers ou les adresses IP.
-   R10 est réservé pour le pointeur de pile.

L'instruction set est volontairement réduit, il comprend les familles d'opération suivantes:
* ALU Instructions
  * 64 bits
  * 32 bits
* Byteswap
* Memory
  * Load
  * Store
* Branch

__Cette librairie est utilisée par Microsoft dans son projet [ebpf-for-windows](https://github.com/microsoft/ebpf-for-windows).__

# Analyse statique

L'analyse débute par une inspection statique du code, dans le répertoire src/vm 3 fichiers intéressants sont identifiés:

- __ubpf_loader.c__, contient une seule fonction **ubpf_load_elf**: 
	- Charge un programme ELF (un format de fichier exécutable binaire utilisé par Linux) dans une VM eBPF. 
	- Elle semble intéressante pour notre analyse, car elle implique de nombreuses opérations sur les pointeurs et la mémoire, ce qui peut potentiellement causer des bugs. 
	- Elle est considérée hors-scope pour cette série d'article mais je pense qu'elle présente plusieurs problèmes de sécurité.

- __ubpf_vm.c__, contient l'nsemble des fonctions utilisée par la VM ubpf, entre autres:
		- __ubpf_create__: utilisé pour créer une machine virtuelle uBPF.
		- __ubpf_load__: charge un programme eBPF dans la VM une fois créée, le programme est passé sous la forme d'un tableau binaire.
		- __ubpf_exec__: execute le programme eBPF chargé dans la VM via l'instruction __ubpf_load__ à la fin de l'execution la valeur du registre r0 est retournée.
		- __ubpf_unload__: décharge un programme eBPF d'une VM, la VM peu alors être réutilisée pour un autre prorgramme.

- __ubpf_jit.c__
	- Deux fonctions associées au compiler JIT:
		- __ubpf_translate__:  compile le code en code machine et le stocke dans le buffer passé en argument.
		- __ubpf_compile__: appelle **ubpf_translate** et retourne un pointeur vers un buffer en mémoire alloué via "calloc" contenant le code machine.
- __test.c__ contient un exemple d'utilisation de la librairie pour une exécution dans une VM et JIT.

## Fonctionnement

Après lecture de la documentation et des sources, la librairie propose deux méthodes d'execution pour les programmes eBPF:
  - De façon dynamique à l'intérieur d'une VM via __upbf_exec__, le bytecode eBPF n'est pas compilé en code machine x86 natif.
  - Compiler le code en instruction x86  via ubpf_compile et ubpf_translatle puis l'executer.

Dans les deux cas une une VM doit être créée via __ubpf_create__ elle peut être détruite via __ubpf_destroy__.

Cette VM peut ensuite être utilisée pour charger du bytecode deux options:
  - __ubpf_load__: charge du bytecode directement.
  - __ubpf_load_elf__: charge un ELF, un parser minimal est intégré.

En ce qui concerne le reste du code, on peut noter que :
-   Une même VM peut être utilisée pour plusieurs eBPF, cependant il est nécessaire d'appeler **ubpf_unload** avant de pouvoir exécuter un nouveau programme. Les fonctions externes ne sont pas désenregistrées.
-   La fonction **ubpf_toggle_bounds_check** permet de définir le flag bounds_check à 1, activant ainsi les contrôles de sécurité pour les opérations mémoires lors de l'exécution de la VM (ne fonctionne pas pour la compilation JIT).
-   Pour protéger contre les attaques ROP, les instructions en mémoire peuvent être XORées une nouvelle fois avec une valeur secrète, cette valeur est définie via la fonction **ubpf_set_pointer_secret**.
-   Il est possible d'enregistrer des fonctions externes appelées depuis le code eBPF via la fonction **ubpf_register**.
-   Il est possible d'accéder en lecture et en écriture aux registres d'une VM à l'aide des fonctions **ubpf_set_registers** et **ubpf_get_registers**.

## Controles de sécurité

Le compiler JIT ne présente aucune mesure de sécurité spécifique, cette partie est normalement prise en charge par programme externe appelé verifier.

Par contre lorsque le programme eBPF est exécuté dans une machine virtuelle dynamique, la fonction **bounds_check** est appelée avant chaque accès à la mémoire (opérations de stockage/chargement). Si l'adresse passée à ces fonctions est située en dehors de la zone mémoire du contexte ou du stakc de la vm, une erreur est retournée et l'exécution du programme est interrompue.

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

Ce controle de sécurité présente un bug classique d'integer overflow, il sera identifié rapidement par notre fuzzer.

Maintenant que l'étape de reconnaissance est terminée nous allons pouvoir développer notre fuzzer et commencer l'analyse dynamique de la VM.

[Attacking uBPF VM - Part 2 Writing the fuzzer - (FR)](https://joachimff.github.io/posts/Attacking-uBPF-VM-Part-2-Writing-the-fuzzer-(FR)/)
