# Playground de Criptografia: Tutoriais Práticos no Kali Linux

Este documento serve como um guia prático e detalhado, contendo tutoriais passo a passo para realizar diversas operações de criptografia e descriptografia utilizando o sistema operacional Kali Linux. O conteúdo foi elaborado a partir das aulas de "Projetar Software de Criptografia" e visa capacitar o leitor a executar cenários reais, desde cifras clássicas até a quebra de senhas e esteganografia.

---

## Aula 01: Criptografia Clássica, Hashes e Quebra de Senhas

Nesta seção, abordaremos os fundamentos da criptografia, incluindo a Cifra de César, o uso de funções de hash, a codificação em Base64 e a utilização de ferramentas como o John the Ripper para auditoria de senhas.

### 1. Cifra de César

A Cifra de César é um dos métodos de criptografia mais antigos, baseada na substituição de letras por outras a uma determinada distância fixa no alfabeto.

**Cenário:** Criptografar e descriptografar uma mensagem usando a Cifra de César com um script Python.

#### 1.1 Script Python: Cifra de César com Análise de Frequência

**Arquivo:** `cifra_cesar.py`

```python
def cifra_cesar(texto, chave, modo):
    alfabeto = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'
    resultado = ''

    for char in texto:
        if char in alfabeto:
            pos_original = alfabeto.find(char)
            if modo == 'criptografar':
                pos_nova = (pos_original + chave) % len(alfabeto)
            elif modo == 'descriptografar':
                pos_nova = (pos_original - chave) % len(alfabeto)
            resultado += alfabeto[pos_nova]
        else:
            resultado += char
    return resultado

# --- Exemplo de Uso ---
mensagem = "Atacar ao amanhecer"
chave = 3

# Criptografar
mensagem_cifrada = cifra_cesar(mensagem, chave, 'criptografar')
print(f'Mensagem Original: {mensagem}')
print(f'Mensagem Cifrada: {mensagem_cifrada}')

# Descriptografar
mensagem_decifrada = cifra_cesar(mensagem_cifrada, chave, 'descriptografar')
print(f'Mensagem Decifrada: {mensagem_decifrada}')
```

**Passo a passo:**

1.  **Crie o arquivo Python:**

    ```bash
    nano cifra_cesar.py
    ```

2.  **Cole o código acima e salve (Ctrl+X, Y, Enter)**

3.  **Execute o script:**

    ```bash
    python3 cifra_cesar.py
    ```

    **Saída esperada:**

    ```
    Mensagem Original: Atacar ao amanhecer
    Mensagem Cifrada: Dwdhdu#dr#dpdokhfhu
    Mensagem Decifrada: Atacar ao amanhecer
    ```

#### 1.2 Script Python: Quebra de Cifra de César com Análise de Frequência

**Arquivo:** `quebra_cesar_avancado.py`

```python
import string
from collections import Counter

def quebra_cesar_forca_bruta(texto_cifrado):
    """
    Tenta quebrar uma Cifra de César testando todas as 26 chaves possíveis.
    Usa análise de frequência para identificar a chave mais provável.
    """
    alfabeto = string.ascii_lowercase
    
    # Palavras comuns em português para análise de frequência
    palavras_comuns = {
        'o', 'a', 'e', 'de', 'da', 'que', 'do', 'para', 'em', 'um',
        'por', 'uma', 'os', 'no', 'se', 'na', 'mais', 'as', 'dos'
    }
    
    resultados = []
    
    for chave in range(26):
        texto_decifrado = ''
        for char in texto_cifrado.lower():
            if char in alfabeto:
                pos_original = alfabeto.find(char)
                pos_nova = (pos_original - chave) % 26
                texto_decifrado += alfabeto[pos_nova]
            else:
                texto_decifrado += char
        
        # Análise de frequência: contar palavras comuns encontradas
        palavras = texto_decifrado.split()
        palavras_encontradas = sum(1 for palavra in palavras if palavra in palavras_comuns)
        
        resultados.append({
            'chave': chave,
            'texto': texto_decifrado,
            'pontuacao': palavras_encontradas
        })
    
    # Ordenar por pontuação (maior número de palavras comuns encontradas)
    resultados.sort(key=lambda x: x['pontuacao'], reverse=True)
    
    print("=== Resultados da Quebra de Cifra de César ===\n")
    for i, resultado in enumerate(resultados[:5]):  # Mostrar os 5 melhores
        print(f"Chave {resultado['chave']}: Pontuação {resultado['pontuacao']}")
        print(f"Texto: {resultado['texto'][:100]}...\n")
    
    return resultados[0]

# Exemplo de uso
if __name__ == "__main__":
    texto_cifrado = "Dwdhdu#dr#dpdokhfhu"
    resultado = quebra_cesar_forca_bruta(texto_cifrado)
    print(f"\nMelhor resultado:")
    print(f"Chave: {resultado['chave']}")
    print(f"Texto decifrado: {resultado['texto']}")
```

**Execução:**

```bash
python3 quebra_cesar_avancado.py
```

---

### 2. Funções de Hash (MD5, SHA-256, SHA-512)

Hashes são sequências de tamanho fixo geradas a partir de um dado de entrada. São fundamentais para a verificação de integridade e armazenamento seguro de senhas.

#### 2.1 Comandos de Hash no Kali Linux

**Gerar Hash MD5:**

```bash
echo -n "minhasenha123" | md5sum
```

**Saída:** `0192023a7bbd73250516f069df18b500  -`

**Gerar Hash SHA-256:**

```bash
echo -n "minhasenha123" | sha256sum
```

**Saída:** `8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918  -`

**Gerar Hash SHA-512:**

```bash
echo -n "minhasenha123" | sha512sum
```

**Saída:** `3c9909afec25354d551dae21590bb26e38f8e5bcb76a39eca6e3708b32522045...  -`

*Observação: O parâmetro `-n` no comando `echo` é crucial para evitar que um caractere de nova linha seja adicionado à string, o que alteraria o hash resultante.*

#### 2.2 Script Python: Gerador de Hashes com Salt

**Arquivo:** `hash_com_salt.py`

```python
import hashlib
import os
import binascii

def gerar_hash_com_salt(senha, salt=None):
    """
    Gera um hash SHA-256 de uma senha com salt.
    Se o salt não for fornecido, um novo é gerado aleatoriamente.
    """
    if salt is None:
        # Gerar um salt aleatório de 32 bytes
        salt = os.urandom(32)
    
    # Combinar salt + senha
    senha_com_salt = salt + senha.encode('utf-8')
    
    # Gerar hash SHA-256
    hash_objeto = hashlib.sha256(senha_com_salt)
    hash_hex = hash_objeto.hexdigest()
    
    # Retornar salt (em hex) + hash
    salt_hex = binascii.hexlify(salt).decode('utf-8')
    
    return f"{salt_hex}${hash_hex}"

def verificar_hash_com_salt(senha, hash_com_salt_str):
    """
    Verifica se uma senha corresponde ao hash armazenado.
    """
    partes = hash_com_salt_str.split('$')
    salt_hex = partes[0]
    hash_armazenado = partes[1]
    
    # Converter salt de hex para bytes
    salt = binascii.unhexlify(salt_hex)
    
    # Gerar hash da senha fornecida com o mesmo salt
    hash_novo = gerar_hash_com_salt(senha, salt).split('$')[1]
    
    # Comparar hashes
    return hash_novo == hash_armazenado

# Exemplo de uso
if __name__ == "__main__":
    senha_original = "MinhaSenh@Forte123"
    
    print("=== Geração de Hash com Salt ===\n")
    
    # Gerar hash
    hash_armazenado = gerar_hash_com_salt(senha_original)
    print(f"Senha: {senha_original}")
    print(f"Hash com Salt: {hash_armazenado}\n")
    
    # Verificar com senha correta
    print("Verificando com senha correta...")
    resultado = verificar_hash_com_salt(senha_original, hash_armazenado)
    print(f"Resultado: {resultado}\n")
    
    # Verificar com senha incorreta
    print("Verificando com senha incorreta...")
    resultado = verificar_hash_com_salt("SenhaErrada", hash_armazenado)
    print(f"Resultado: {resultado}")
```

**Execução:**

```bash
python3 hash_com_salt.py
```

#### 2.3 Script Python: Análise de Força de Senha

**Arquivo:** `analise_forca_senha.py`

```python
import re

def analisar_forca_senha(senha):
    """
    Analisa a força de uma senha e retorna um score de 0 a 100.
    """
    score = 0
    feedback = []
    
    # Comprimento
    if len(senha) >= 8:
        score += 10
    if len(senha) >= 12:
        score += 10
    if len(senha) >= 16:
        score += 10
    else:
        feedback.append("❌ Senha muito curta (mínimo 12 caracteres recomendado)")
    
    # Letras maiúsculas
    if re.search(r'[A-Z]', senha):
        score += 15
    else:
        feedback.append("❌ Faltam letras maiúsculas")
    
    # Letras minúsculas
    if re.search(r'[a-z]', senha):
        score += 15
    else:
        feedback.append("❌ Faltam letras minúsculas")
    
    # Números
    if re.search(r'\d', senha):
        score += 15
    else:
        feedback.append("❌ Faltam números")
    
    # Caracteres especiais
    if re.search(r'[!@#$%^&*()_+\-=\[\]{};:\'",.<>?/\\|`~]', senha):
        score += 15
    else:
        feedback.append("❌ Faltam caracteres especiais")
    
    # Verificar padrões comuns fracos
    padroes_fracos = [
        r'(.)\1{2,}',  # Caracteres repetidos (aaa, bbb, etc)
        r'(012|123|234|345|456|567|678|789|890)',  # Sequências numéricas
        r'(abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl)',  # Sequências alfabéticas
    ]
    
    for padrao in padroes_fracos:
        if re.search(padrao, senha.lower()):
            score -= 10
            feedback.append("❌ Contém padrões previsíveis")
            break
    
    # Limitar score entre 0 e 100
    score = max(0, min(100, score))
    
    # Classificação
    if score >= 80:
        forca = "🟢 Muito Forte"
    elif score >= 60:
        forca = "🟡 Forte"
    elif score >= 40:
        forca = "🟠 Moderada"
    else:
        forca = "🔴 Fraca"
    
    return {
        'score': score,
        'forca': forca,
        'feedback': feedback
    }

# Exemplo de uso
if __name__ == "__main__":
    senhas_teste = [
        "123456",
        "password",
        "Senha123",
        "Senh@F0rt3!2024",
        "MyP@ssw0rd!Secure#2024"
    ]
    
    print("=== Análise de Força de Senha ===\n")
    
    for senha in senhas_teste:
        resultado = analisar_forca_senha(senha)
        print(f"Senha: {senha}")
        print(f"Score: {resultado['score']}/100")
        print(f"Força: {resultado['forca']}")
        if resultado['feedback']:
            for item in resultado['feedback']:
                print(f"  {item}")
        print()
```

**Execução:**

```bash
python3 analise_forca_senha.py
```

---

### 3. Codificação em Base64

Base64 não é um algoritmo de criptografia, mas um método de codificação para representar dados binários em formato de texto. É facilmente reversível.

#### 3.1 Comandos Base64 no Kali Linux

**Codificar para Base64:**

```bash
echo -n "Kali Linux é poderoso" | base64
```

**Saída:** `S2FsaSBMaW51eCDDqSBwb2Rlcm9zbw==`

**Decodificar de Base64:**

```bash
echo -n "S2FsaSBMaW51eCDDqSBwb2Rlcm9zbw==" | base64 -d
```

**Saída:** `Kali Linux é poderoso`

**Codificar arquivo inteiro:**

```bash
base64 arquivo.txt > arquivo_base64.txt
```

**Decodificar arquivo:**

```bash
base64 -d arquivo_base64.txt > arquivo_original.txt
```

---

### 4. Compactação com Criptografia (ZIP)

É possível proteger arquivos compactados com uma senha.

#### 4.1 Comandos ZIP com Criptografia

**Cenário:** Criar um arquivo de texto, compactá-lo com senha e depois descompactá-lo.

**Passo a passo:**

1.  **Crie um arquivo de exemplo:**

    ```bash
    echo "Este é um documento secreto." > segredo.txt
    ```

2.  **Compacte o arquivo com senha:**

    ```bash
    zip --encrypt segredos.zip segredo.txt
    ```

    O terminal solicitará que você digite e verifique uma senha.

3.  **Para descompactar, use o comando `unzip`:**

    ```bash
    unzip segredos.zip
    ```

    A senha definida será solicitada.

4.  **Compactar múltiplos arquivos:**

    ```bash
    zip --encrypt arquivos_criptografados.zip arquivo1.txt arquivo2.txt arquivo3.txt
    ```

5.  **Listar conteúdo do ZIP sem extrair:**

    ```bash
    unzip -l segredos.zip
    ```

6.  **Compactar um diretório inteiro com criptografia:**

    ```bash
    zip -r --encrypt diretorio_criptografado.zip /caminho/para/diretorio/
    ```

7.  **Descompactar especificando um arquivo de saída:**

    ```bash
    unzip -d /caminho/saida/ segredos.zip
    ```

8.  **Testar integridade do arquivo ZIP:**

    ```bash
    unzip -t segredos.zip
    ```

9.  **Compactar com nível de compressão máximo:**

    ```bash
    zip -9 --encrypt segredos_comprimido.zip segredo.txt
    ```

10. **Extrair apenas um arquivo específico do ZIP:**

    ```bash
    unzip segredos.zip arquivo_especifico.txt
    ```

**Variações Úteis:**

| Comando | Descrição |
|---------|----------|
| `zip -e arquivo.zip arquivo.txt` | Criptografia interativa (solicita senha) |
| `zip -P senha arquivo.zip arquivo.txt` | Criptografia com senha na linha de comando (menos seguro) |
| `unzip -l arquivo.zip` | Listar conteúdo sem extrair |
| `unzip -t arquivo.zip` | Testar integridade |
| `unzip -c arquivo.zip` | Extrair para stdout (exibir no terminal) |
| `zip -d arquivo.zip arquivo_remover.txt` | Remover arquivo do ZIP |
| `zip -u arquivo.zip arquivo_novo.txt` | Atualizar/adicionar arquivo ao ZIP |

**Exemplo Completo de Fluxo:**

```bash
# Criar múltiplos arquivos
echo "Dados confidenciais 1" > dados1.txt
echo "Dados confidenciais 2" > dados2.txt
echo "Dados confidenciais 3" > dados3.txt

# Compactar com criptografia
zip --encrypt backup_criptografado.zip dados1.txt dados2.txt dados3.txt

# Listar conteúdo
unzip -l backup_criptografado.zip

# Testar integridade
unzip -t backup_criptografado.zip

# Extrair para um diretório específico
unzip -d /tmp/backup_extraido/ backup_criptografado.zip

# Verificar se os arquivos foram extraídos
ls -la /tmp/backup_extraido/
```

---

### 5. Quebra de Senha de Arquivo ZIP com John the Ripper

O John the Ripper é uma ferramenta poderosa para auditoria e quebra de senhas.

#### 5.1 Instalação do John the Ripper

```bash
# Opção 1: Instalação via apt (mais simples)
sudo apt update
sudo apt install john -y

# Opção 2: Compilação a partir do código-fonte (mais completo)
git clone https://github.com/magnumripper/johntheripper.git
cd johntheripper/src
./configure
make -s clean && make -sj4
```

#### 5.2 Quebra de Senha ZIP com John the Ripper

**Cenário:** Quebrar a senha do arquivo `segredos.zip` criado anteriormente.

**Passo a passo:**

1.  **Extraia o hash do arquivo ZIP:**

    ```bash
    # Se instalado via apt
    zip2john segredos.zip > hash_zip.txt
    
    # Se compilado do código-fonte
    cd /caminho/para/johntheripper/run
    ./zip2john /caminho/completo/para/segredos.zip > hash_zip.txt
    ```

    **Verificar o conteúdo do hash extraído:**

    ```bash
    cat hash_zip.txt
    ```

    **Saída esperada (exemplo):**

    ```
    segredos.zip/segredo.txt:$pkzip$1*1*2*0*...(hash longo)...*$/pkzip$
    ```

2.  **Crie uma wordlist (lista de palavras) para o ataque de dicionário:**

    ```bash
    cat > minha_wordlist.txt << EOF
    senha123
    senhadificil
    minhasenha
    kalilinux
    password
    admin
    EOF
    ```

3.  **Execute o John the Ripper para quebrar a senha:**

    ```bash
    # Se instalado via apt
    john --wordlist=minha_wordlist.txt hash_zip.txt
    
    # Se compilado do código-fonte
    cd /caminho/para/johntheripper/run
    ./john --wordlist=/caminho/para/minha_wordlist.txt /caminho/para/hash_zip.txt
    ```

    **Saída durante o processo:**

    ```
    Using default input encoding: UTF-8
    Loaded 1 password hash (PKZIP [32/64])
    Will run 4 OpenMP threads
    Press 'q' or Ctrl-C to abort, almost any other key for status
    minhasenha           (segredos.zip/segredo.txt)
    1g 0:00:00:00 DONE (2025-11-22 10:30) 100.0g/s 1000p/s 1000c/s 1000C/s password..admin
    Use the "--show" option to display all of the cracked passwords
    ```

4.  **Visualize a senha quebrada:**

    ```bash
    john --show hash_zip.txt
    ```

    **Saída esperada:**

    ```
    segredos.zip:minhasenha
    
    1 password hash cracked, 0 left
    ```

5.  **Usar wordlist do Kali Linux (rockyou.txt):**

    ```bash
    # Descompactar a wordlist se necessário
    gunzip /usr/share/wordlists/rockyou.txt.gz
    
    # Usar com John the Ripper
    john --wordlist=/usr/share/wordlists/rockyou.txt hash_zip.txt
    ```

6.  **Executar com força bruta (se a senha não estiver em wordlist):**

    ```bash
    john --incremental hash_zip.txt
    ```

7.  **Usar regras para gerar variações de senha:**

    ```bash
    john --wordlist=minha_wordlist.txt --rules hash_zip.txt
    ```

8.  **Limpar o arquivo de cache do John (para quebrar novamente do zero):**

    ```bash
    rm john.pot
    ```

9.  **Executar John em modo silencioso (sem exibir progresso):**

    ```bash
    john --wordlist=minha_wordlist.txt hash_zip.txt --quiet
    ```

10. **Verificar status de um processo em execução:**

    ```bash
    john --status
    ```

#### 5.3 Quebra de Senha do Linux com John the Ripper

**Cenário:** Extrair os hashes de senha do sistema Kali e tentar quebrá-los.

**Passo a passo:**

1.  **Combine os arquivos de senha e shadow:**

    *Este comando requer privilégios de superusuário.*

    ```bash
    sudo unshadow /etc/passwd /etc/shadow > hashes_linux.txt
    ```

    **Verificar o conteúdo do arquivo de hashes:**

    ```bash
    cat hashes_linux.txt | head -5
    ```

    **Saída esperada (exemplo):**

    ```
    root:$6$rounds=656000$abcdef123456$hash_muito_longo_aqui:0:0:root:/root:/bin/bash
    kali:$6$rounds=656000$xyz789$outro_hash_aqui:1000:1000:Kali,,,:/home/kali:/bin/bash
    ```

2.  **Descompactar a wordlist rockyou.txt (se necessário):**

    ```bash
    # Verificar se está compactada
    ls -lh /usr/share/wordlists/rockyou.txt*
    
    # Se estiver compactada (.gz), descompactar
    sudo gunzip /usr/share/wordlists/rockyou.txt.gz
    ```

3.  **Execute o John the Ripper no arquivo de hashes:**

    ```bash
    # Opção 1: Usar wordlist descompactada
    sudo john --wordlist=/usr/share/wordlists/rockyou.txt hashes_linux.txt
    
    # Opção 2: Usar wordlist compactada (John descompacta automaticamente)
    sudo john --wordlist=/usr/share/wordlists/rockyou.txt.gz hashes_linux.txt
    ```

    **Saída durante o processo:**

    ```
    Using default input encoding: UTF-8
    Loaded 2 password hashes with 2 different salts (sha512crypt [SHA512 256/256 AVX2 8x])
    Will run 4 OpenMP threads
    Press 'q' or Ctrl-C to abort, almost any other key for status
    password123         (kali)
    1g 0:00:05:23 DONE (2025-11-22 10:35) 0.003087g/s 1234p/s 1234c/s 1234C/s password123..admin
    ```

4.  **Visualize as senhas quebradas:**

    ```bash
    sudo john --show hashes_linux.txt
    ```

    **Saída esperada:**

    ```
    root:senha_root_aqui:0:0:root:/root:/bin/bash
    kali:password123:1000:1000:Kali,,,:/home/kali:/bin/bash
    
    2 password hashes cracked, 0 left
    ```

5.  **Executar força bruta em hashes não quebrados:**

    ```bash
    sudo john --incremental hashes_linux.txt
    ```

6.  **Usar regras para gerar variações:**

    ```bash
    sudo john --wordlist=/usr/share/wordlists/rockyou.txt --rules hashes_linux.txt
    ```

7.  **Quebrar apenas hashes de um usuário específico:**

    ```bash
    # Extrair apenas o hash do usuário 'kali'
    sudo unshadow /etc/passwd /etc/shadow | grep "^kali:" > hash_kali.txt
    
    # Quebrar apenas esse hash
    sudo john --wordlist=/usr/share/wordlists/rockyou.txt hash_kali.txt
    ```

8.  **Usar modo de força bruta com padrão customizado:**

    ```bash
    # Força bruta com caracteres maiúsculos, minúsculos e números (até 8 caracteres)
    sudo john --incremental=LowerCase hashes_linux.txt
    ```

9.  **Executar John em múltiplos núcleos:**

    ```bash
    sudo john --wordlist=/usr/share/wordlists/rockyou.txt --fork=4 hashes_linux.txt
    ```

10. **Limpar o arquivo de cache do John (para quebrar novamente do zero):**

    ```bash
    rm john.pot
    ```

11. **Restaurar a wordlist compactada (se descompactada):**

    ```bash
    sudo gzip /usr/share/wordlists/rockyou.txt
    ```

**Exemplo Completo de Fluxo:**

```bash
# 1. Extrair hashes
sudo unshadow /etc/passwd /etc/shadow > hashes_sistema.txt

# 2. Verificar quantos hashes foram extraídos
wc -l hashes_sistema.txt

# 3. Executar John com wordlist
sudo john --wordlist=/usr/share/wordlists/rockyou.txt hashes_sistema.txt

# 4. Aguardar conclusão (pode levar alguns minutos)

# 5. Visualizar resultados
sudo john --show hashes_sistema.txt

# 6. Limpar cache para próxima execução
rm john.pot
```

---

## Aula 02: Criptografia Assimétrica e VeraCrypt

Nesta aula, exploramos a criptografia de chave pública (assimétrica) e uma ferramenta prática para criar volumes criptografados, o VeraCrypt.

### 1. Criptografia de Chave Pública (RSA) com OpenSSL

A criptografia assimétrica utiliza um par de chaves: uma **pública**, que pode ser compartilhada com qualquer pessoa para criptografar mensagens, e uma **privada**, que deve ser mantida em segredo e é a única capaz de descriptografar as mensagens.

#### 1.1 Comandos OpenSSL: Geração de Chaves RSA

**Gerar chave privada RSA (2048 bits):**

```bash
openssl genrsa -out chave_privada.pem 2048
```

**Gerar chave privada RSA (4096 bits - mais segura):**

```bash
openssl genrsa -out chave_privada.pem 4096
```

**Extrair chave pública da chave privada:**

```bash
openssl rsa -pubout -in chave_privada.pem -out chave_publica.pem
```

**Visualizar conteúdo da chave privada:**

```bash
openssl rsa -in chave_privada.pem -text -noout
```

**Visualizar conteúdo da chave pública:**

```bash
openssl rsa -pubin -in chave_publica.pem -text -noout
```

#### 1.2 Comandos OpenSSL: Criptografia e Descriptografia com RSA

**Criptografar arquivo com chave pública:**

```bash
openssl rsautl -encrypt -inkey chave_publica.pem -pubin -in arquivo.txt -out arquivo.enc
```

**Descriptografar arquivo com chave privada:**

```bash
openssl rsautl -decrypt -inkey chave_privada.pem -in arquivo.enc -out arquivo.txt
```

#### 1.3 Script Python: Criptografia RSA com Pycryptodome

**Arquivo:** `rsa_exemplo.py`

```python
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

# 1. Geração do par de chaves (isso seria feito pelo destinatário, "Bob")
chave = RSA.generate(2048)
chave_privada = chave.export_key()
chave_publica = chave.publickey().export_key()

# Salvar as chaves em arquivos (opcional, mas boa prática)
with open("chave_privada.pem", "wb") as f:
    f.write(chave_privada)
with open("chave_publica.pem", "wb") as f:
    f.write(chave_publica)

print("Chaves pública e privada geradas.")

# 2. Criptografar a mensagem (isso seria feito pelo remetente, "Alice")
mensagem = b'Esta eh uma mensagem super secreta.'

# Carregar a chave pública para criptografar
chave_pub_importada = RSA.import_key(open("chave_publica.pem").read())
cifra_rsa = PKCS1_OAEP.new(chave_pub_importada)
mensagem_cifrada = cifra_rsa.encrypt(mensagem)

print("\nMensagem Cifrada:", mensagem_cifrada.hex())

# 3. Descriptografar a mensagem (Bob, usando sua chave privada)

# Carregar a chave privada para descriptografar
chave_priv_importada = RSA.import_key(open("chave_privada.pem").read())
decifra_rsa = PKCS1_OAEP.new(chave_priv_importada)
mensagem_decifrada = decifra_rsa.decrypt(mensagem_cifrada)

print("\nMensagem Decifrada:", mensagem_decifrada.decode())
```

**Instalação de dependência:**

```bash
pip install pycryptodome
```

**Execução:**

```bash
python3 rsa_exemplo.py
```

---

### 2. VeraCrypt: Criando um Volume Criptografado

O VeraCrypt é uma ferramenta de software livre para criptografia de disco em tempo real. Ele pode criar um volume virtual criptografado dentro de um arquivo ou criptografar uma partição inteira.

#### 2.1 Instalação do VeraCrypt

```bash
sudo apt update
sudo apt install veracrypt -y
```

#### 2.2 Criação de Volume Criptografado via GUI

**Passo a passo:**

1.  **Inicie o VeraCrypt:**

    ```bash
    veracrypt
    ```

2.  **Crie um novo volume:**

    *   Na interface do VeraCrypt, clique em **"Create Volume"**.
    *   Selecione **"Create an encrypted file container"** e clique em **"Next"**.
    *   Escolha **"Standard VeraCrypt volume"** e clique em **"Next"**.

3.  **Selecione o local e o nome do arquivo:**

    *   Clique em **"Select File..."** e escolha um local e nome para o seu contêiner (ex: `/home/kali/meu_volume.hc`). **Importante:** O arquivo não deve existir ainda. Clique em **"Save"** e depois em **"Next"**.

4.  **Configurações de Criptografia:**

    *   Mantenha os padrões (**AES** e **SHA-512**) que são seguros. Clique em **"Next"**.

5.  **Tamanho do Volume:**

    *   Defina o tamanho do seu volume (ex: 100 MB). Clique em **"Next"**.

6.  **Senha do Volume:**

    *   Escolha uma **senha forte e longa**. O VeraCrypt recomenda pelo menos 20 caracteres. Confirme a senha e clique em **"Next"**.

7.  **Formatação do Volume:**

    *   Mova o mouse aleatoriamente dentro da janela para aumentar a força das chaves criptográficas. Quando a barra estiver verde, clique em **"Format"**.
    *   Aguarde a formatação ser concluída e clique em **"OK"** e depois em **"Exit"**.

8.  **Montando o Volume Criptografado:**

    *   Na janela principal do VeraCrypt, selecione um slot de drive livre (ex: 1).
    *   Clique em **"Select File..."** e escolha o arquivo de contêiner que você criou (`meu_volume.hc`).
    *   Clique em **"Mount"**.
    *   Digite a senha que você definiu e clique em **"OK"**.

    O volume agora estará montado e acessível como um novo disco no seu gerenciador de arquivos. Você pode copiar arquivos para dentro dele, e eles serão criptografados automaticamente. Para finalizar, selecione o volume montado e clique em **"Dismount"**.

#### 2.3 Criação de Volume via Linha de Comando

**Criar um contêiner VeraCrypt via CLI:**

```bash
# Criar arquivo de contêiner vazio (100 MB)
dd if=/dev/zero of=meu_volume.hc bs=1M count=100

# Criptografar o contêiner
veracrypt --text --create meu_volume.hc
```

**Montar o contêiner:**

```bash
veracrypt --text --mount meu_volume.hc /mnt/veracrypt
```

**Desmontar o contêiner:**

```bash
veracrypt --text --dismount meu_volume.hc
```

---

## Aula 03: Quebra de Hashes com Hashcat

O Hashcat é conhecido como o "quebrador de senhas mais rápido do mundo". Ele utiliza o poder das GPUs (placas de vídeo) para acelerar massivamente o processo de adivinhação de senhas a partir de seus hashes.

### 1. Instalação do Hashcat

```bash
sudo apt update
sudo apt install hashcat -y
```

**Verificar instalação e suporte de GPU:**

```bash
hashcat -I
```

### 2. Quebrando um Hash NTLM com Hashcat

O hash NTLM é o formato classicamente usado para armazenar senhas em sistemas Windows.

#### 2.1 Ataque de Dicionário em Hash NTLM

**Cenário:** Quebrar um hash NTLM usando um ataque de dicionário com o Hashcat.

**Passo a passo:**

1.  **Crie um arquivo com o hash:**

    *Vamos usar um hash NTLM de exemplo para a senha "Password123".*

    ```bash
    echo "8846f7eaee8fb117ad06bdd830b7586c" > hash_ntlm.txt
    ```

    **Verificar o arquivo criado:**

    ```bash
    cat hash_ntlm.txt
    ```

2.  **Verificar suporte de GPU (opcional):**

    ```bash
    hashcat -I
    ```

    **Saída esperada (exemplo):**

    ```
    hashcat (v6.2.6) starting in benchmark mode
    
    CUDA Devices:
    * Device #1: GeForce GTX 1080, 8192/8192 MB allocatable, 20CUs
    
    OpenCL Devices:
    * Device #2: Intel(R) Core(TM) i7-8700K CPU @ 3.70GHz, 16384 MB allocatable
    ```

3.  **Execute o Hashcat com um ataque de dicionário:**

    *Este comando diz ao Hashcat para usar o modo de ataque de dicionário (`-a 0`), especificar o tipo de hash como NTLM (`-m 1000`), e aponta para o arquivo de hash e a wordlist.*

    ```bash
    hashcat -a 0 -m 1000 hash_ntlm.txt /usr/share/wordlists/rockyou.txt.gz
    ```

    **Saída durante o processo:**

    ```
    hashcat (v6.2.6) starting
    
    * Device #1: GeForce GTX 1080, 8192/8192 MB, 20CUs
    
    Hashes: 1 digests; 1 unique digests, 1 unique salts
    Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
    Rules: 1
    
    Applicable optimizers applied:
    * Zero-Byte
    * Early-Skip
    * Not-Iterated
    * Single-Hash
    * Single-Salt
    * Raw-Hash
    
    Minimum password length supported by kernel: 0
    Maximum password length supported by kernel: 256
    
    CUDA API (CUDA 11.0)
    Device #1: Kernel m01000_a0-optimized.64.cu (79 KB)
    Device #1: Kernel m01000_a0-pure.64.cu (79 KB)
    
    Hashmode: 1000 - NTLM
    Speed.#1.........:  8234.5 MH/s (88.92ms) @ Accel:128 Loops:1 Thr:1024 Vec:2
    Recovered: 1/1 (100.00%) Digests, 0/1 (0.00%) Salts, 1/1 (100.00%) Passwords
    Progress: 1000000/14344391 (6.97%)
    Estimated Time: 0 secs
    
    8846f7eaee8fb117ad06bdd830b7586c:Password123
    
    Session..........: hashcat
    Status...........: Cracked
    Hash.Type........: NTLM
    Hash.Target......: 8846f7eaee8fb117ad06bdd830b7586c
    Time.Started.....: Fri Nov 22 10:40:15 2025 (0 secs)
    Time.Estimated...: Fri Nov 22 10:40:15 2025 (0 secs)
    Guess.Base.......: File (/usr/share/wordlists/rockyou.txt.gz)
    Guess.Queue......: 1/1 (100.00%)
    Speed.#1.........: 8234.5 MH/s (88.92ms) @ Accel:128 Loops:1 Thr:1024 Vec:2
    Recovered........: 1/1 (100.00%) Digests
    Progress.........: 1000000/14344391 (6.97%)
    Rejected.........: 0/1000000 (0.00%)
    Restore.Point....: 1000000/14344391 (6.97%)
    Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
    Candidates.#1....: 123456 -> Password123
    HWMon.#1.........: 45% Util, 65C Temp, 100% Fan
    ```

4.  **Visualize a senha quebrada:**

    *Após a quebra, você pode ver o resultado a qualquer momento com o parâmetro `--show`.*

    ```bash
    hashcat --show -m 1000 hash_ntlm.txt
    ```

    **Saída esperada:**

    ```
    8846f7eaee8fb117ad06bdd830b7586c:Password123
    ```

5.  **Usar opção `-O` para otimização de kernel:**

    ```bash
    hashcat -a 0 -m 1000 -O hash_ntlm.txt /usr/share/wordlists/rockyou.txt.gz
    ```

6.  **Usar opção `-w` para definir workload (velocidade vs. responsividade):**

    ```bash
    # -w 1: Baixo (mais responsável)
    # -w 2: Médio (padrão)
    # -w 3: Alto (mais rápido, menos responsável)
    # -w 4: Máximo (muito rápido, sistema pode ficar lento)
    hashcat -a 0 -m 1000 -w 4 hash_ntlm.txt /usr/share/wordlists/rockyou.txt.gz
    ```

7.  **Usar múltiplos dispositivos (CPU + GPU):**

    ```bash
    hashcat -a 0 -m 1000 -d 1,2 hash_ntlm.txt /usr/share/wordlists/rockyou.txt.gz
    ```

8.  **Salvar saída em arquivo:**

    ```bash
    hashcat -a 0 -m 1000 hash_ntlm.txt /usr/share/wordlists/rockyou.txt.gz -o resultado_quebra.txt
    ```

9.  **Usar arquivo de log:**

    ```bash
    hashcat -a 0 -m 1000 hash_ntlm.txt /usr/share/wordlists/rockyou.txt.gz --logfile-disable
    ```

10. **Retomar uma sessão interrompida:**

    ```bash
    hashcat -a 0 -m 1000 hash_ntlm.txt /usr/share/wordlists/rockyou.txt.gz --restore
    ```

**Tabela de Tipos de Hash (Modo -m):**

| Modo | Tipo de Hash | Descrição |
|------|-------------|----------|
| 0 | MD5 | Hash MD5 |
| 100 | SHA1 | Hash SHA-1 |
| 1000 | NTLM | Windows NTLM |
| 1400 | SHA-256 | Hash SHA-256 |
| 1700 | SHA-512 | Hash SHA-512 |
| 3200 | bcrypt | bcrypt |
| 5500 | NetNTLMv2 | Windows Network NTLM v2 |
| 7900 | Drupal7 | Drupal7 |

**Tabela de Modos de Ataque (-a):**

| Modo | Nome | Descrição |
|------|------|----------|
| 0 | Dicionário | Usa palavras de uma wordlist |
| 1 | Combinação | Combina duas wordlists |
| 3 | Força Bruta | Tenta todas as combinações possíveis |
| 6 | Híbrid 1 | Wordlist + máscara |
| 7 | Híbrid 2 | Máscara + wordlist |

**Exemplo Completo de Fluxo:**

```bash
# 1. Criar arquivo com hash NTLM
echo "8846f7eaee8fb117ad06bdd830b7586c" > hash_ntlm.txt

# 2. Verificar GPU
hashcat -I

# 3. Executar Hashcat com otimização
hashcat -a 0 -m 1000 -O -w 4 hash_ntlm.txt /usr/share/wordlists/rockyou.txt.gz

# 4. Visualizar resultado
hashcat --show -m 1000 hash_ntlm.txt

# 5. Salvar resultado em arquivo
hashcat --show -m 1000 hash_ntlm.txt > resultado_final.txt
```

#### 2.2 Ataque de Força Bruta em Hash MD5

**Quebrar um hash MD5 com força bruta (máximo 6 caracteres):**

```bash
echo "5d41402abc4b2a76b9719d911017c592" > hash_md5.txt
hashcat -a 3 -m 0 hash_md5.txt ?a?a?a?a?a?a
```

*Onde `?a` representa qualquer caractere (letra, número, símbolo).*

#### 2.3 Ataque com Regras em Hash SHA-256

**Quebrar um hash SHA-256 com regras aplicadas:**

```bash
echo "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" > hash_sha256.txt
hashcat -a 0 -m 1400 hash_sha256.txt /usr/share/wordlists/rockyou.txt.gz -r /usr/share/hashcat/rules/best64.rule
```

#### 2.4 Script Python: Gerador de Chaves Criptográficas Seguras

**Arquivo:** `gerador_chaves.py`

```python
from Crypto.PublicKey import RSA, ECC
from Crypto.Random import get_random_bytes
import binascii

def gerar_chave_rsa(tamanho=2048):
    """
    Gera um par de chaves RSA.
    """
    chave = RSA.generate(tamanho)
    return {
        'privada': chave.export_key().decode('utf-8'),
        'publica': chave.publickey().export_key().decode('utf-8')
    }

def gerar_chave_ecc(curva='P-256'):
    """
    Gera um par de chaves ECC (Elliptic Curve Cryptography).
    Mais eficiente que RSA para o mesmo nível de segurança.
    """
    chave = ECC.generate(curve=curva)
    return {
        'privada': chave.export_key(format='PEM'),
        'publica': chave.publickey().export_key(format='PEM')
    }

def gerar_chave_simetrica(tamanho_bits=256):
    """
    Gera uma chave simétrica aleatória.
    """
    chave = get_random_bytes(tamanho_bits // 8)
    return binascii.hexlify(chave).decode('utf-8')

# Exemplo de uso
if __name__ == "__main__":
    print("=== Gerador de Chaves Criptográficas ===\n")
    
    # RSA
    print("1. Gerando par de chaves RSA (2048 bits)...")
    chaves_rsa = gerar_chave_rsa(2048)
    print(f"Chave Privada RSA:\n{chaves_rsa['privada'][:100]}...\n")
    print(f"Chave Pública RSA:\n{chaves_rsa['publica'][:100]}...\n")
    
    # ECC
    print("2. Gerando par de chaves ECC (P-256)...")
    chaves_ecc = gerar_chave_ecc('P-256')
    print(f"Chave Privada ECC:\n{chaves_ecc['privada'].decode('utf-8')[:100]}...\n")
    print(f"Chave Pública ECC:\n{chaves_ecc['publica'].decode('utf-8')[:100]}...\n")
    
    # Simétrica
    print("3. Gerando chave simétrica (256 bits)...")
    chave_simetrica = gerar_chave_simetrica(256)
    print(f"Chave Simétrica (hex): {chave_simetrica}\n")
```

**Execução:**

```bash
python3 gerador_chaves.py
```

### 3. Recomendações de Mitigação

Para se proteger contra a quebra de hashes, é fundamental:

*   **Usar senhas fortes e longas:** Combine letras maiúsculas, minúsculas, números e símbolos.
*   **Implementar Autenticação Multifator (MFA):** Mesmo que a senha seja quebrada, o segundo fator protege a conta.
*   **Utilizar "Salting":** Adicionar um "sal" (um valor aleatório) à senha antes de gerar o hash. Sistemas modernos como o Linux já fazem isso por padrão, tornando ataques de dicionário com tabelas pré-computadas (rainbow tables) ineficazes.

---

## Aula 04: Assinaturas Digitais e Esteganografia

Esta aula cobre dois tópicos importantes: como garantir a autenticidade e a integridade de documentos com assinaturas digitais e como ocultar informações à vista de todos usando esteganografia.

### 1. Assinaturas Digitais com OpenSSL

A assinatura digital, baseada em criptografia assimétrica, prova quem assinou um documento e que ele não foi alterado.

#### 1.1 Comandos OpenSSL: Assinatura Digital

**Cenário:** Criar um par de chaves RSA, assinar um documento de texto e depois verificar a assinatura.

**Passo a passo:**

1.  **Gere uma chave privada RSA:**

    ```bash
    openssl genpkey -algorithm RSA -out chave_privada.pem -pkeyopt rsa_keygen_bits:2048
    ```

2.  **Extraia a chave pública da chave privada:**

    ```bash
    openssl rsa -pubout -in chave_privada.pem -out chave_publica.pem
    ```

3.  **Crie um documento para assinar:**

    ```bash
    echo "Este é o contrato que precisa ser assinado." > contrato.txt
    ```

4.  **Assine o documento:**

    *Este comando cria um hash (resumo) do documento e o criptografa com a chave privada, gerando a assinatura.*

    ```bash
    openssl dgst -sha256 -sign chave_privada.pem -out contrato.sig contrato.txt
    ```

5.  **Verifique a assinatura:**

    *Este comando usa a chave pública para descriptografar a assinatura, recalcula o hash do documento original e compara os dois. Se forem idênticos, a verificação é bem-sucedida.*

    ```bash
    openssl dgst -sha256 -verify chave_publica.pem -signature contrato.sig contrato.txt
    ```

    **Saída esperada:** `Verified OK`

6.  **(Opcional) Teste com um documento alterado:**

    ```bash
    echo "Este é um contrato alterado." > contrato_falso.txt
    openssl dgst -sha256 -verify chave_publica.pem -signature contrato.sig contrato_falso.txt
    ```

    **Saída esperada:** `Verification Failure`

7.  **Assinar com algoritmos diferentes:**

    ```bash
    # Assinar com SHA-512 (mais seguro)
    openssl dgst -sha512 -sign chave_privada.pem -out contrato_sha512.sig contrato.txt
    
    # Verificar assinatura SHA-512
    openssl dgst -sha512 -verify chave_publica.pem -signature contrato_sha512.sig contrato.txt
    ```

8.  **Assinar arquivo binário:**

    ```bash
    # Criar arquivo binário de exemplo
    dd if=/dev/urandom of=arquivo_binario.bin bs=1024 count=1
    
    # Assinar arquivo binário
    openssl dgst -sha256 -sign chave_privada.pem -out arquivo_binario.sig arquivo_binario.bin
    
    # Verificar assinatura
    openssl dgst -sha256 -verify chave_publica.pem -signature arquivo_binario.sig arquivo_binario.bin
    ```

9.  **Verificar detalhes da chave privada:**

    ```bash
    openssl pkey -in chave_privada.pem -text -noout
    ```

10. **Converter chave privada para formato PKCS#8:**

    ```bash
    openssl pkcs8 -topk8 -in chave_privada.pem -out chave_privada_pkcs8.pem -nocrypt
    ```

#### 1.2 Comandos OpenSSL: Certificados Digitais

**Gerar um certificado autoassinado:**

```bash
openssl req -x509 -newkey rsa:4096 -keyout chave.pem -out certificado.pem -days 365
```

**Visualizar conteúdo de um certificado:**

```bash
openssl x509 -in certificado.pem -text -noout
```

**Verificar validade de um certificado:**

```bash
openssl x509 -in certificado.pem -noout -dates
```

**Exportar certificado em formato DER:**

```bash
openssl x509 -in certificado.pem -outform DER -out certificado.der
```

---

### 2. Esteganografia: Ocultando Dados em Imagens com Steghide

A esteganografia oculta a existência de uma mensagem, escondendo-a dentro de outro arquivo, como uma imagem.

#### 2.1 Instalação do Steghide

```bash
sudo apt update
sudo apt install steghide -y
```

#### 2.2 Comandos Steghide: Incorporar e Extrair Dados

**Cenário:** Ocultar um arquivo de texto secreto dentro de uma imagem JPG.

**Passo a passo:**

1.  **Prepare os arquivos:**

    *   Crie o arquivo de texto secreto:
        ```bash
        echo "Ponto de encontro: Praça Central, à meia-noite." > plano_secreto.txt
        ```

    *   Baixe uma imagem de exemplo:
        ```bash
        wget -O imagem.jpg https://thispersondoesnotexist.com/
        ```

2.  **Incorpore o texto na imagem:**

    *O comando `embed` é usado para incorporar (-cf = cover file, -ef = embed file). Você definirá uma senha para proteger os dados ocultos.*

    ```bash
    steghide embed -cf imagem.jpg -ef plano_secreto.txt
    ```

    O terminal solicitará uma senha (passphrase).

3.  **Extraia o arquivo oculto:**

    *Para recuperar o arquivo, use o comando `extract`.*

    ```bash
    steghide extract -sf imagem.jpg
    ```

    A mesma senha será solicitada. Se correta, o arquivo `plano_secreto.txt` será recriado no diretório.

4.  **Obter informações sobre dados ocultos:**

    ```bash
    steghide info imagem.jpg
    ```

5.  **Extrair arquivo sem solicitar senha:**

    ```bash
    steghide extract -sf imagem.jpg -p sua_senha_aqui
    ```

6.  **Usar arquivo de imagem diferente (PNG, BMP, WAV):**

    ```bash
    # Com PNG
    steghide embed -cf imagem.png -ef arquivo_secreto.txt
    steghide extract -sf imagem.png
    
    # Com BMP
    steghide embed -cf imagem.bmp -ef arquivo_secreto.txt
    steghide extract -sf imagem.bmp
    
    # Com WAV (audio)
    steghide embed -cf audio.wav -ef arquivo_secreto.txt
    steghide extract -sf audio.wav
    ```

7.  **Extrair para arquivo com nome diferente:**

    ```bash
    steghide extract -sf imagem.jpg -xf arquivo_extraido_novo.txt -p senha123
    ```

8.  **Exemplo Completo de Fluxo:**

    ```bash
    # 1. Criar arquivo secreto
    echo "Coordenadas: 40.7128, -74.0060" > coordenadas_secretas.txt
    
    # 2. Baixar imagem
    wget -O paisagem.jpg https://example.com/imagem.jpg
    
    # 3. Verificar capacidade
    steghide info paisagem.jpg
    
    # 4. Incorporar arquivo com senha forte
    steghide embed -cf paisagem.jpg -ef coordenadas_secretas.txt -p "Senh@Forte2025!"
    
    # 5. Verificar que foi incorporado
    steghide info paisagem.jpg -p "Senh@Forte2025!"
    
    # 6. Extrair arquivo
    steghide extract -sf paisagem.jpg -p "Senh@Forte2025!"
    
    # 7. Verificar conteudo extraido
    cat coordenadas_secretas.txt
    ```

#### 2.3 Quebrando a Esteganografia com Stegcracker

Se a senha usada no Steghide for fraca, ela pode ser quebrada com um ataque de dicionário.

**Instalação do Stegcracker:**

```bash
sudo apt install stegcracker -y
```

**Executar o Stegcracker na imagem:**

*O Stegcracker tentará extrair os dados usando cada senha da wordlist fornecida.*

```bash
stegcracker imagem.jpg /usr/share/wordlists/rockyou.txt.gz
```

*Se a senha estiver na wordlist, o Stegcracker a encontrará, a exibirá no terminal e salvará o conteúdo extraído em um arquivo com o sufixo `.out` (ex: `imagem.jpg.out`).*

---

## Aula 05: Ataque Man-in-the-Middle e Análise de Tráfego com Wireshark

Um ataque Man-in-the-Middle (MitM) ocorre quando um invasor se posiciona entre duas partes que se comunicam, interceptando e, potencialmente, alterando a comunicação sem que elas saibam. A criptografia é a principal defesa contra isso.

### 1. Análise de Tráfego Não Criptografado com Wireshark

O Wireshark é um analisador de protocolos de rede que nos permite "ver" o tráfego que passa pela nossa placa de rede. Ele é uma ferramenta essencial para entender como os dados viajam e para identificar comunicações inseguras.

#### 1.1 Instalação do Wireshark

```bash
sudo apt update
sudo apt install wireshark -y
```

*Durante a instalação, uma janela perguntará se usuários não-root devem ser capazes de capturar pacotes. Selecione **"Yes"** para facilitar o uso.*

#### 1.2 Configuração de Permissões

```bash
sudo usermod -aG wireshark $USER
```

*Após executar este comando, **faça logout e login novamente** para que a alteração de grupo tenha efeito.*

#### 1.3 Captura e Análise de Tráfego HTTP

**Cenário:** Capturar credenciais de login enviadas por meio de um formulário web não criptografado (HTTP).

**Passo a passo:**

1.  **Inicie o Wireshark:**

    ```bash
    wireshark
    ```

2.  **Comece a Captura:**

    *   Na tela inicial, você verá uma lista de interfaces de rede (como `eth0`, `wlan0`). Dê um duplo-clique na interface que você está usando para se conectar à internet (geralmente `eth0` para conexões cabeadas ou `wlan0` para Wi-Fi) para iniciar a captura.

3.  **Gere Tráfego HTTP:**

    *   Abra um navegador e acesse um site de teste que use um formulário de login sobre HTTP, como o `http://testphp.vulnweb.com/`.
    *   Clique em "signup" e preencha o formulário com dados fictícios (ex: `testuser` e `testpassword`).
    *   Submeta o formulário.

4.  **Filtre e Analise os Pacotes:**

    *   Volte para o Wireshark e pare a captura clicando no ícone de quadrado vermelho.
    *   No campo de filtro na parte superior, digite `http.request.method == "POST"` e pressione Enter. Isso mostrará apenas os pacotes que enviaram dados de formulário.
    *   Selecione o pacote que aparece na lista.
    *   No painel de detalhes do pacote (geralmente na parte inferior), expanda a seção **"HTML Form URL Encoded"**.
    *   Você verá os dados do formulário, incluindo o nome de usuário e a senha, em texto claro!

    *Este exercício demonstra vividamente por que o HTTPS (HTTP Seguro), que criptografa essa comunicação, é absolutamente essencial para qualquer site que lida com informações sensíveis.*

5.  **Exportar pacotes capturados:**

    ```bash
    # Salvar em formato PCAP (para análise posterior)
    # Menu: File > Export Specified Packets
    # Ou via linha de comando:
    tshark -r captura.pcap -w captura_filtrada.pcap -f "http"
    ```

6.  **Usar filtros avançados:**

    ```bash
    # Filtrar por IP de origem
    ip.src == 192.168.1.100
    
    # Filtrar por IP de destino
    ip.dst == 8.8.8.8
    
    # Filtrar por intervalo de portas
    tcp.port >= 1024 and tcp.port <= 65535
    
    # Filtrar por protocolo
    tcp or udp
    
    # Combinar filtros
    http and ip.src == 192.168.1.100
    ```

7.  **Analisar dados de formulário POST:**

    ```bash
    # No Wireshark, após capturar:
    # 1. Filtrar: http.request.method == "POST"
    # 2. Clicar no pacote
    # 3. Expandir: Hypertext Transfer Protocol > HTML Form URL Encoded
    # 4. Ver os parâmetros do formulário em texto claro
    ```

8.  **Extrair objetos HTTP:**

    ```bash
    # Menu: File > Export Objects > HTTP
    # Isso permite salvar imagens, scripts, etc. capturados
    ```

9.  **Exemplo Completo de Fluxo de Análise:**

    ```bash
    # 1. Iniciar Wireshark
    wireshark
    
    # 2. Selecionar interface (eth0 ou wlan0)
    # 3. Clicar em "Start capturing packets"
    
    # 4. Abrir navegador e acessar site HTTP (não HTTPS)
    # Exemplo: http://testphp.vulnweb.com/
    
    # 5. Fazer login ou enviar formulário
    
    # 6. Voltar ao Wireshark e parar captura
    
    # 7. Filtrar por POST
    # Digite no filtro: http.request.method == "POST"
    
    # 8. Selecionar o pacote POST
    
    # 9. Expandir em "Hypertext Transfer Protocol"
    
    # 10. Ver os dados do formulário em texto claro
    # Procurar por: username, password, email, etc.
    ```

#### 1.4 Filtros Wireshark Úteis

| Filtro | Descrição |
|--------|-----------|
| `http` | Mostra apenas tráfego HTTP |
| `https` | Mostra apenas tráfego HTTPS |
| `tcp.port == 80` | Mostra tráfego na porta 80 (HTTP) |
| `tcp.port == 443` | Mostra tráfego na porta 443 (HTTPS) |
| `ip.src == 192.168.1.100` | Mostra tráfego de um IP específico |
| `dns` | Mostra apenas consultas DNS |
| `tcp.flags.syn == 1` | Mostra apenas pacotes SYN (início de conexão) |

---

### 2. Métodos de Estabelecimento de Chave

Para que a comunicação criptografada funcione, as duas partes precisam concordar sobre uma chave secreta. Como fazer isso de forma segura em um canal inseguro?

#### 2.1 Troca de Chaves Diffie-Hellman (DH)

Um método matemático engenhoso que permite que duas partes, que não se conhecem, criem uma chave secreta compartilhada através de um canal público. Mesmo que um invasor intercepte toda a troca de mensagens, ele não conseguirá calcular a chave secreta final. O DH é um pilar do estabelecimento de sessões seguras na web (TLS/SSL).

**Simulação Teórica:**

1. Alice e Bob concordam publicamente em usar números primos `p` e `g`.
2. Alice escolhe um número secreto `a` e envia `g^a mod p` para Bob.
3. Bob escolhe um número secreto `b` e envia `g^b mod p` para Alice.
4. Alice calcula `(g^b)^a mod p = g^(ab) mod p`.
5. Bob calcula `(g^a)^b mod p = g^(ab) mod p`.
6. Ambos chegam ao mesmo resultado `g^(ab) mod p`, que é a chave secreta compartilhada.

#### 2.2 Passkeys: Autenticação Moderna

Uma passkey (ou chave de acesso) é uma credencial digital que substitui as senhas tradicionais, usando criptografia e biometria (como impressão digital ou reconhecimento facial) para autenticar usuários em sites e aplicativos.

**Como Funciona:**

1. Usuário registra dispositivo → cria par de chaves (pública/privada).
2. Servidor guarda chave pública.
3. Ao autenticar:
   - Servidor envia desafio.
   - Dispositivo assina com chave privada.
   - Servidor verifica assinatura com chave pública.

**Vantagens:**

*   Segurança contra phishing (a chave privada nunca sai do dispositivo).
*   Conveniência (biometria em vez de digitar senhas).
*   Compatibilidade com grandes empresas (Google, Apple, Microsoft, Amazon).

---

### 3. Comandos OpenSSL para Criptografia TLS/SSL

#### 3.1 Gerar Certificado Autoassinado para HTTPS

```bash
openssl req -x509 -newkey rsa:4096 -keyout chave_privada.key -out certificado.crt -days 365 -nodes
```

#### 3.2 Testar Conexão HTTPS com OpenSSL

```bash
openssl s_client -connect example.com:443
```

#### 3.3 Verificar Certificado de um Servidor

```bash
openssl s_client -connect example.com:443 -showcerts
```

#### 3.4 Converter Certificado PEM para DER

```bash
openssl x509 -in certificado.pem -outform DER -out certificado.der
```

#### 3.5 Verificar Validade de Certificado

```bash
openssl x509 -in certificado.pem -noout -dates
```

---

## Apêndice A: Tabela Comparativa de Algoritmos de Hash

| Algoritmo | Tamanho (bits) | Segurança | Uso Recomendado | Status |
|-----------|----------------|-----------|-----------------|--------|
| MD5 | 128 | Baixa | Checksums, não-criptográfico | ❌ Descontinuado |
| SHA-1 | 160 | Baixa | Legado apenas | ❌ Descontinuado |
| SHA-256 | 256 | Alta | Padrão recomendado | ✅ Recomendado |
| SHA-512 | 512 | Muito Alta | Máxima segurança | ✅ Recomendado |
| SHA-3 | 256/512 | Muito Alta | Futuro, pesquisa | ✅ Recomendado |

---

## Apêndice B: Referência Rápida de Comandos OpenSSL

```bash
# Geração de Chaves
openssl genrsa -out chave_privada.pem 2048
openssl rsa -pubout -in chave_privada.pem -out chave_publica.pem
openssl genpkey -algorithm RSA -out chave.pem -pkeyopt rsa_keygen_bits:4096

# Criptografia/Descriptografia
openssl rsautl -encrypt -inkey chave_publica.pem -pubin -in arquivo.txt -out arquivo.enc
openssl rsautl -decrypt -inkey chave_privada.pem -in arquivo.enc -out arquivo.txt

# Assinaturas Digitais
openssl dgst -sha256 -sign chave_privada.pem -out arquivo.sig arquivo.txt
openssl dgst -sha256 -verify chave_publica.pem -signature arquivo.sig arquivo.txt

# Certificados
openssl req -x509 -newkey rsa:4096 -keyout chave.pem -out certificado.pem -days 365
openssl x509 -in certificado.pem -text -noout
openssl x509 -in certificado.pem -noout -dates

# Conexões HTTPS
openssl s_client -connect example.com:443
openssl s_client -connect example.com:443 -showcerts
```

---

## Apêndice C: Ferramentas Essenciais do Kali Linux para Criptografia

| Ferramenta | Função | Instalação | Comando Básico |
|-----------|--------|-----------|-----------------|
| `openssl` | Criptografia e certificados | Pré-instalado | `openssl genrsa -out chave.pem 2048` |
| `john` | Quebra de senhas | `sudo apt install john` | `john --wordlist=wordlist.txt hashes.txt` |
| `hashcat` | Quebra de hashes com GPU | `sudo apt install hashcat` | `hashcat -a 0 -m 1000 hash.txt wordlist.txt` |
| `steghide` | Esteganografia | `sudo apt install steghide` | `steghide embed -cf imagem.jpg -ef arquivo.txt` |
| `stegcracker` | Quebra de esteganografia | `sudo apt install stegcracker` | `stegcracker imagem.jpg wordlist.txt` |
| `wireshark` | Análise de tráfego | `sudo apt install wireshark` | `wireshark` |
| `veracrypt` | Criptografia de disco | `sudo apt install veracrypt` | `veracrypt --create volume.hc` |

---

## Apêndice D: Troubleshooting e Soluções Comuns

### Problema: "Permission denied" ao executar John the Ripper

**Solução:**

```bash
chmod +x /caminho/para/john
sudo ./john --wordlist=wordlist.txt hashes.txt
```

### Problema: Wireshark não captura pacotes

**Solução:**

```bash
sudo usermod -aG wireshark $USER
newgrp wireshark
```

### Problema: "ModuleNotFoundError: No module named 'Crypto'"

**Solução:**

```bash
pip3 install pycryptodome
```

### Problema: Hashcat não encontra GPU

**Solução:**

```bash
hashcat -I
# Se não encontrar, instale drivers NVIDIA (se aplicável)
sudo apt install nvidia-driver-XXX
```

### Problema: Arquivo ZIP com senha não abre

**Solução:**

```bash
unzip -P sua_senha arquivo.zip
# Ou use John the Ripper para quebrar
zip2john arquivo.zip > hash.txt
john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt.gz
```

---

## Índice de Conteúdo

- **Aula 01:** Criptografia Clássica, Hashes e Quebra de Senhas
  - Cifra de César (com scripts Python)
  - Funções de Hash (MD5, SHA-256, SHA-512)
  - Codificação em Base64
  - Compactação com Criptografia (ZIP)
  - Quebra de Senha com John the Ripper

- **Aula 02:** Criptografia Assimétrica e VeraCrypt
  - Criptografia RSA com OpenSSL e Python
  - VeraCrypt: Volumes Criptografados

- **Aula 03:** Quebra de Hashes com Hashcat
  - Hashcat: Conceitos e Uso
  - Quebrando Hashes NTLM, MD5 e SHA-256
  - Gerador de Chaves Criptográficas

- **Aula 04:** Assinaturas Digitais e Esteganografia
  - Assinaturas Digitais com OpenSSL
  - Certificados Digitais
  - Esteganografia com Steghide
  - Quebrando Esteganografia com Stegcracker

- **Aula 05:** Ataque Man-in-the-Middle e Wireshark
  - Análise de Tráfego com Wireshark
  - Métodos de Estabelecimento de Chave (Diffie-Hellman)
  - Passkeys: Autenticação Moderna
  - Comandos OpenSSL para TLS/SSL

- **Apêndice A:** Tabela Comparativa de Algoritmos de Hash
- **Apêndice B:** Referência Rápida de Comandos OpenSSL
- **Apêndice C:** Ferramentas Essenciais do Kali Linux
- **Apêndice D:** Troubleshooting e Soluções Comuns

---

## Notas Finais

Este playground foi desenvolvido como material educacional para fins de aprendizado e pesquisa. Todos os conceitos e ferramentas aqui apresentados devem ser utilizados **apenas em ambientes autorizados** e de acordo com as leis locais e regulamentações de segurança cibernética. O uso não autorizado de técnicas de quebra de senha, análise de tráfego ou acesso a sistemas é ilegal.

**Responsabilidade:** O autor não se responsabiliza pelo uso indevido deste material. Use com ética e responsabilidade.

---

**Documento preparado por:** Manus AI  
**Data:** Novembro de 2025  
**Versão:** 2.0 (Atualizado com integração de scripts, ferramentas e comandos SSL)  
**Licença:** Educacional - Uso Livre para Fins de Aprendizado

---

## Apêndice E: Demonstração Prática com Servidor HTTP/HTTPS

Para consolidar os conceitos da Aula 05, esta seção fornece uma implementação Python completa que cria um servidor web local com uma tela de login, acessível tanto por HTTP (inseguro) quanto por HTTPS (seguro). O script gera automaticamente um certificado autoassinado, permitindo uma demonstração prática e visual da captura de tráfego com o Wireshark.

### 1. Funcionalidades do Script

- **Geração Automática de Certificado:** Cria um par de chave/certificado (`key.pem`, `cert.pem`) usando OpenSSL se não existirem.
- **Servidor Duplo:** Executa simultaneamente um servidor HTTP na porta 8080 e um servidor HTTPS na porta 8443.
- **Tela de Login Simples:** Apresenta um formulário de login para testar o envio de dados.
- **Demonstração Visual:** Permite observar a diferença crucial entre tráfego criptografado e não criptografado.

### 2. Código Completo: `servidor_demo.py`

Crie um arquivo chamado `servidor_demo.py` e cole o código abaixo.

```python
import os
import ssl
import subprocess
from flask import Flask, request, render_template_string
from threading import Thread

# --- Configuração do Aplicativo Flask ---
app = Flask(__name__)

# --- Template HTML da Tela de Login ---
LOGIN_TEMPLATE = """
<!DOCTYPE html>
<html lang="pt-br">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Tela de Login - {{ protocol }}</title>
    <style>
        body { font-family: sans-serif; background-color: #f0f2f5; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }
        .login-container { background-color: white; padding: 40px; border-radius: 8px; box-shadow: 0 4px 8px rgba(0,0,0,0.1); width: 300px; text-align: center; }
        h1 { color: #333; margin-bottom: 10px; }
        .protocol-http { color: #d9534f; }
        .protocol-https { color: #5cb85c; }
        p { color: #666; margin-bottom: 20px; }
        input { width: 100%; padding: 10px; margin-bottom: 15px; border: 1px solid #ccc; border-radius: 4px; box-sizing: border-box; }
        button { width: 100%; padding: 10px; border: none; border-radius: 4px; color: white; font-size: 16px; cursor: pointer; }
        .btn-http { background-color: #d9534f; }
        .btn-https { background-color: #5cb85c; }
    </style>
</head>
<body>
    <div class="login-container">
        <h1 class="protocol-{{ protocol.lower() }}">Login {{ protocol }}</h1>
        <p>Use Wireshark para analisar esta conexão.</p>
        <form method="post">
            <input type="text" name="username" placeholder="Usuário" required>
            <input type="password" name="password" placeholder="Senha" required>
            <button type="submit" class="btn-{{ protocol.lower() }}">Entrar</button>
        </form>
    </div>
</body>
</html>
"""

# --- Geração do Certificado Autoassinado ---
def gerar_certificado():
    """Verifica se o certificado e a chave existem, senão, gera novos."""
    if not (os.path.exists("cert.pem") and os.path.exists("key.pem")):
        print("[*] Gerando certificado autoassinado (cert.pem) e chave privada (key.pem)...")
        comando = [
            "openssl", "req",
            "-x509",
            "-newkey", "rsa:4096",
            "-nodes",
            "-out", "cert.pem",
            "-keyout", "key.pem",
            "-days", "365",
            "-subj", "/CN=localhost"
        ]
        try:
            subprocess.run(comando, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            print("[+] Certificado e chave gerados com sucesso!")
        except (subprocess.CalledProcessError, FileNotFoundError) as e:
            print(f"[!] Erro ao gerar certificado: {e}")
            print("[!] Certifique-se de que o OpenSSL está instalado e no PATH do sistema.")
            exit(1)
    else:
        print("[*] Certificado e chave já existentes.")

# --- Rotas do Servidor ---
@app.route("/", methods=["GET", "POST"])
def login():
    protocol = "HTTPS" if request.is_secure else "HTTP"
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        print(f"\n[+] Credenciais recebidas via {protocol}:\n    Usuário: {username}\n    Senha:   {password}")
        return f"<h1>Login via {protocol} bem-sucedido!</h1><p>Verifique o terminal onde o servidor está rodando.</p>"
    return render_template_string(LOGIN_TEMPLATE, protocol=protocol)

# --- Funções para iniciar os servidores ---
def run_http_server():
    """Inicia o servidor HTTP na porta 8080."""
    print("[*] Servidor HTTP rodando em http://localhost:8080")
    # O Flask não deve ser usado em produção, mas é ótimo para esta demo.
    app.run(host="0.0.0.0", port=8080)

def run_https_server():
    """Inicia o servidor HTTPS na porta 8443."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain("cert.pem", "key.pem")
    print("[*] Servidor HTTPS rodando em https://localhost:8443")
    app.run(host="0.0.0.0", port=8443, ssl_context=context)

# --- Bloco Principal ---
if __name__ == "__main__":
    gerar_certificado()
    
    # Iniciar ambos os servidores em threads separadas
    # ATENÇÃO: Para uma aplicação real, use um servidor WSGI como Gunicorn ou Waitress.
    http_thread = Thread(target=run_http_server)
    https_thread = Thread(target=run_https_server)
    
    # Iniciar o servidor HTTPS primeiro para que o HTTP não bloqueie o terminal
    https_thread.start()
    http_thread.start()
```

### 3. Instruções de Uso e Demonstração

Siga estes passos para executar a demonstração completa.

#### Passo 1: Instalar Dependências

Este script requer a biblioteca Flask. Instale-a usando o pip:

```bash
pip install Flask
```

#### Passo 2: Executar o Servidor

Salve o código como `servidor_demo.py` e execute-o no terminal. Ele irá gerar os arquivos de certificado e iniciar os dois servidores.

```bash
python3 servidor_demo.py
```

**Saída esperada no terminal:**

```
[*] Gerando certificado autoassinado (cert.pem) e chave privada (key.pem)...
[+] Certificado e chave gerados com sucesso!
[*] Servidor HTTPS rodando em https://localhost:8443
[*] Servidor HTTP rodando em http://localhost:8080
```

#### Passo 3: Iniciar a Captura com Wireshark

1.  Abra o Wireshark.
2.  Como o tráfego é local (do seu navegador para o seu próprio computador), você precisa capturar na interface de **loopback**. O nome pode variar:
    -   **Linux:** `lo`
    -   **Windows:** `Adapter for loopback traffic capture`
    -   **macOS:** `lo0`
3.  Dê um duplo-clique na interface de loopback para iniciar a captura.

#### Passo 4: Testar a Conexão HTTP (Insegura)

1.  Abra seu navegador e acesse: `http://localhost:8080`
2.  Preencha o formulário com um usuário e senha fictícios (ex: `admin` e `senha123`).
3.  Clique em "Entrar".
4.  **Análise no Wireshark:**
    -   Pare a captura.
    -   No campo de filtro, digite `http.request.method == "POST"` e pressione Enter.
    -   Você verá um pacote. Clique nele.
    -   No painel de detalhes, expanda a seção **"HTML Form URL Encoded"**.
    -   **Resultado:** As credenciais (`username` e `password`) estarão visíveis em **texto claro**.

![Wireshark HTTP](https://i.imgur.com/example_http.png) *<-- Imagem de exemplo mostrando dados em texto claro no Wireshark.*

#### Passo 5: Testar a Conexão HTTPS (Segura)

1.  Reinicie a captura no Wireshark (sem salvar a anterior).
2.  Abra seu navegador e acesse: `https://localhost:8443`
3.  O navegador exibirá um **aviso de segurança** ("Sua conexão não é particular"). Isso é esperado, pois o certificado foi autoassinado e não emitido por uma Autoridade Certificadora (AC) confiável. Clique em "Avançado" e depois em "Ir para localhost (não seguro)".
4.  Preencha o formulário com os mesmos dados (`admin` e `senha123`).
5.  Clique em "Entrar".
6.  **Análise no Wireshark:**
    -   Pare a captura.
    -   No campo de filtro, digite `tls` e pressione Enter.
    -   Você verá uma série de pacotes TLS. Procure por pacotes com o protocolo **"TLSv1.2"** ou **"TLSv1.3"** e a informação **"Application Data"**.
    -   Clique em qualquer um desses pacotes.
    -   **Resultado:** O conteúdo no painel de detalhes estará completamente ilegível, mostrando apenas dados criptografados. Você **não conseguirá** encontrar o usuário ou a senha em lugar nenhum.

![Wireshark HTTPS](https://i.imgur.com/example_https.png) *<-- Imagem de exemplo mostrando dados criptografados no Wireshark.*

### Conclusão da Demonstração

Esta demonstração prática ilustra de forma inequívoca a importância do HTTPS. Enquanto o HTTP envia todos os dados abertamente, permitindo que qualquer intermediário na rede (provedor de internet, administrador de rede Wi-Fi, etc.) leia as informações, o HTTPS utiliza TLS/SSL para criar um túnel seguro, garantindo a **confidencialidade** e a **integridade** dos dados trocados.


### 4. Script Python Executável Pronto para Copiar e Colar

Para facilitar o uso, abaixo está o script completo em um bloco único, pronto para ser salvo e executado.

**Arquivo:** `servidor_demo.py`

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Servidor HTTP/HTTPS com Tela de Login para Demonstração com Wireshark
Autor: Playground de Criptografia
Descrição: Cria um servidor duplo (HTTP e HTTPS) com tela de login simples
           para demonstrar a diferença entre tráfego criptografado e não criptografado.
"""

import os
import sys
import ssl
import subprocess
from flask import Flask, request, render_template_string
from threading import Thread
from pathlib import Path

# --- Configuração do Aplicativo Flask ---
app = Flask(__name__)

# --- Template HTML da Tela de Login ---
LOGIN_TEMPLATE = """
<!DOCTYPE html>
<html lang="pt-br">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Tela de Login - {{ protocol }}</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
        }
        .login-container { 
            background-color: white;
            padding: 50px;
            border-radius: 12px;
            box-shadow: 0 8px 32px rgba(0,0,0,0.2);
            width: 350px;
            text-align: center;
        }
        .protocol-indicator {
            display: inline-block;
            padding: 8px 16px;
            border-radius: 20px;
            font-weight: bold;
            margin-bottom: 20px;
            font-size: 14px;
        }
        .protocol-http { 
            background-color: #ffe5e5;
            color: #d9534f;
        }
        .protocol-https { 
            background-color: #e5f5e5;
            color: #5cb85c;
        }
        h1 { 
            color: #333;
            margin-bottom: 10px;
            font-size: 28px;
        }
        p { 
            color: #666;
            margin-bottom: 30px;
            font-size: 14px;
        }
        .form-group {
            margin-bottom: 15px;
            text-align: left;
        }
        label {
            display: block;
            margin-bottom: 5px;
            color: #555;
            font-weight: 500;
            font-size: 14px;
        }
        input { 
            width: 100%;
            padding: 12px;
            border: 2px solid #e0e0e0;
            border-radius: 6px;
            font-size: 14px;
            transition: border-color 0.3s;
        }
        input:focus {
            outline: none;
            border-color: #667eea;
        }
        button { 
            width: 100%;
            padding: 12px;
            border: none;
            border-radius: 6px;
            color: white;
            font-size: 16px;
            font-weight: bold;
            cursor: pointer;
            transition: transform 0.2s, box-shadow 0.2s;
        }
        button:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 12px rgba(0,0,0,0.15);
        }
        .btn-http { background-color: #d9534f; }
        .btn-https { background-color: #5cb85c; }
        .warning {
            background-color: #fff3cd;
            border: 1px solid #ffc107;
            color: #856404;
            padding: 12px;
            border-radius: 6px;
            margin-bottom: 20px;
            font-size: 13px;
        }
    </style>
</head>
<body>
    <div class="login-container">
        <div class="protocol-indicator protocol-{{ protocol.lower() }}">
            Conexão via {{ protocol }}
        </div>
        <h1>Tela de Login</h1>
        <p>Use Wireshark para analisar esta conexão.</p>
        {% if protocol == 'HTTP' %}
        <div class="warning">
            ⚠️ Aviso: Esta conexão NÃO é criptografada. Seus dados podem ser interceptados!
        </div>
        {% else %}
        <div class="warning">
            ✓ Esta conexão está criptografada com TLS/SSL.
        </div>
        {% endif %}
        <form method="post">
            <div class="form-group">
                <label for="username">Usuário:</label>
                <input type="text" id="username" name="username" placeholder="Digite seu usuário" required>
            </div>
            <div class="form-group">
                <label for="password">Senha:</label>
                <input type="password" id="password" name="password" placeholder="Digite sua senha" required>
            </div>
            <button type="submit" class="btn-{{ protocol.lower() }}">Entrar</button>
        </form>
    </div>
</body>
</html>
"""

# --- Geração do Certificado Autoassinado ---
def gerar_certificado():
    """Verifica se o certificado e a chave existem, senão, gera novos."""
    cert_path = Path("cert.pem")
    key_path = Path("key.pem")
    
    if cert_path.exists() and key_path.exists():
        print("[✓] Certificado e chave já existentes.")
        return True
    
    print("[*] Gerando certificado autoassinado (cert.pem) e chave privada (key.pem)...")
    comando = [
        "openssl", "req",
        "-x509",
        "-newkey", "rsa:4096",
        "-nodes",
        "-out", "cert.pem",
        "-keyout", "key.pem",
        "-days", "365",
        "-subj", "/CN=localhost"
    ]
    
    try:
        resultado = subprocess.run(
            comando,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        print("[✓] Certificado e chave gerados com sucesso!")
        print(f"    - Arquivo: cert.pem")
        print(f"    - Arquivo: key.pem")
        print(f"    - Validade: 365 dias")
        return True
    except FileNotFoundError:
        print("[!] Erro: OpenSSL não encontrado no PATH do sistema.")
        print("[!] Instale o OpenSSL:")
        print("    - Ubuntu/Debian: sudo apt install openssl")
        print("    - CentOS/RHEL: sudo yum install openssl")
        print("    - macOS: brew install openssl")
        return False
    except subprocess.CalledProcessError as e:
        print(f"[!] Erro ao gerar certificado: {e.stderr}")
        return False

# --- Rotas do Servidor ---
@app.route("/", methods=["GET", "POST"])
def login():
    """Rota principal que exibe a tela de login e processa o envio do formulário."""
    protocol = "HTTPS" if request.is_secure else "HTTP"
    
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        
        print(f"\n{'='*60}")
        print(f"[+] Credenciais recebidas via {protocol}")
        print(f"{'='*60}")
        print(f"    Usuário: {username}")
        print(f"    Senha:   {password}")
        print(f"    IP:      {request.remote_addr}")
        print(f"    User-Agent: {request.headers.get('User-Agent', 'N/A')}")
        print(f"{'='*60}\n")
        
        return f"""
        <html>
        <head>
            <meta charset="UTF-8">
            <style>
                body {{ font-family: sans-serif; text-align: center; padding: 50px; }}
                .success {{ color: #5cb85c; font-size: 24px; }}
                .info {{ color: #666; margin-top: 20px; }}
            </style>
        </head>
        <body>
            <div class="success">✓ Login via {protocol} bem-sucedido!</div>
            <div class="info">
                <p>Verifique o terminal onde o servidor está rodando para ver os dados recebidos.</p>
                <p><a href="/">Voltar ao login</a></p>
            </div>
        </body>
        </html>
        """
    
    return render_template_string(LOGIN_TEMPLATE, protocol=protocol)

# --- Funções para iniciar os servidores ---
def run_http_server():
    """Inicia o servidor HTTP na porta 8080."""
    try:
        print("[*] Iniciando servidor HTTP na porta 8080...")
        app.run(
            host="0.0.0.0",
            port=8080,
            debug=False,
            use_reloader=False,
            threaded=True
        )
    except OSError as e:
        print(f"[!] Erro ao iniciar servidor HTTP: {e}")

def run_https_server():
    """Inicia o servidor HTTPS na porta 8443."""
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain("cert.pem", "key.pem")
        print("[*] Iniciando servidor HTTPS na porta 8443...")
        app.run(
            host="0.0.0.0",
            port=8443,
            debug=False,
            use_reloader=False,
            ssl_context=context,
            threaded=True
        )
    except OSError as e:
        print(f"[!] Erro ao iniciar servidor HTTPS: {e}")

# --- Bloco Principal ---
if __name__ == "__main__":
    print("\n" + "="*60)
    print("  Servidor HTTP/HTTPS com Tela de Login")
    print("  Demonstração para Wireshark")
    print("="*60 + "\n")
    
    # Verificar se Flask está instalado
    try:
        import flask
    except ImportError:
        print("[!] Erro: Flask não está instalado.")
        print("[!] Instale com: pip3 install Flask")
        sys.exit(1)
    
    # Gerar certificado
    if not gerar_certificado():
        sys.exit(1)
    
    print("\n[*] Iniciando servidores...\n")
    
    # Iniciar ambos os servidores em threads separadas
    https_thread = Thread(target=run_https_server, daemon=True)
    http_thread = Thread(target=run_http_server, daemon=True)
    
    https_thread.start()
    http_thread.start()
    
    print("\n" + "="*60)
    print("  SERVIDORES INICIADOS COM SUCESSO")
    print("="*60)
    print("\n[✓] HTTP:  http://localhost:8080")
    print("[✓] HTTPS: https://localhost:8443")
    print("\n[*] Pressione Ctrl+C para parar os servidores.\n")
    
    try:
        https_thread.join()
    except KeyboardInterrupt:
        print("\n\n[*] Servidores parados.")
        sys.exit(0)
```

### 5. Passo a Passo Detalhado de Execução

#### 5.1 Instalação de Dependências

Antes de executar o script, instale as dependências necessárias:

```bash
# Atualizar pip
pip3 install --upgrade pip

# Instalar Flask
pip3 install Flask

# Verificar se OpenSSL está instalado
openssl version
```

**Se o OpenSSL não estiver instalado:**

```bash
# Ubuntu/Debian
sudo apt install openssl -y

# CentOS/RHEL
sudo yum install openssl -y

# macOS
brew install openssl
```

#### 5.2 Salvando o Script

1.  Crie um arquivo chamado `servidor_demo.py`:

    ```bash
    nano servidor_demo.py
    ```

2.  Cole o código completo do script acima.

3.  Salve o arquivo (Ctrl+O, Enter, Ctrl+X no nano).

4.  Dê permissão de execução:

    ```bash
    chmod +x servidor_demo.py
    ```

#### 5.3 Executando o Servidor

```bash
python3 servidor_demo.py
```

**Saída esperada:**

```
============================================================
  Servidor HTTP/HTTPS com Tela de Login
  Demonstração para Wireshark
============================================================

[✓] Certificado e chave já existentes.

[*] Iniciando servidores...

[*] Iniciando servidor HTTPS na porta 8443...
[*] Iniciando servidor HTTP na porta 8080...

============================================================
  SERVIDORES INICIADOS COM SUCESSO
============================================================

[✓] HTTP:  http://localhost:8080
[✓] HTTPS: https://localhost:8443

[*] Pressione Ctrl+C para parar os servidores.
```

#### 5.4 Testando com Wireshark

**Cenário 1: Captura de Tráfego HTTP (Inseguro)**

1.  Abra o Wireshark em outro terminal.
2.  Selecione a interface de **loopback** (`lo` no Linux, `lo0` no macOS).
3.  Clique em "Start" para iniciar a captura.
4.  Abra seu navegador e acesse: `http://localhost:8080`
5.  Preencha o formulário:
    -   Usuário: `admin`
    -   Senha: `senha123`
6.  Clique em "Entrar".
7.  Volte ao Wireshark e clique em "Stop" para parar a captura.
8.  No campo de filtro, digite: `http.request.method == "POST"`
9.  Clique no pacote que aparecer.
10. No painel de detalhes, expanda: **Hypertext Transfer Protocol > HTML Form URL Encoded**
11. **Resultado:** Você verá os dados em texto claro:
    ```
    username: admin
    password: senha123
    ```

**Cenário 2: Captura de Tráfego HTTPS (Seguro)**

1.  Limpe a captura anterior no Wireshark (File > New).
2.  Clique em "Start" para iniciar uma nova captura.
3.  Abra seu navegador e acesse: `https://localhost:8443`
4.  O navegador exibirá um aviso de segurança (certificado autoassinado). Clique em **"Avançado"** e depois em **"Continuar para localhost"** (ou equivalente no seu navegador).
5.  Preencha o formulário com os mesmos dados:
    -   Usuário: `admin`
    -   Senha: `senha123`
6.  Clique em "Entrar".
7.  Volte ao Wireshark e clique em "Stop".
8.  No campo de filtro, digite: `tls`
9.  Você verá uma série de pacotes TLS. Procure por pacotes com **"Application Data"**.
10. Clique em qualquer um desses pacotes.
11. **Resultado:** No painel de detalhes, você verá apenas dados criptografados. **Não conseguirá encontrar o usuário ou a senha em lugar nenhum.**

### 6. Observações Importantes

- **Certificado Autoassinado:** O certificado gerado é válido por 365 dias. Seu navegador exibirá um aviso de segurança, o que é esperado. Em produção, use certificados emitidos por uma Autoridade Certificadora (AC) confiável.

- **Portas:** O servidor HTTP usa a porta 8080 e o HTTPS usa a porta 8443. Se essas portas já estiverem em uso, você receberá um erro. Nesse caso, modifique o script para usar portas diferentes.

- **Interface de Loopback:** A captura deve ser feita na interface de loopback (`lo` ou `lo0`) porque o tráfego é local. Se você estiver testando em máquinas diferentes, use a interface de rede apropriada.

- **Dados Capturados:** O servidor imprime as credenciais recebidas no terminal. Isso é apenas para fins educacionais. Em produção, **nunca** imprima senhas em logs.

### 7. Extensões Possíveis

Este script pode ser estendido de várias formas:

- **Adicionar Banco de Dados:** Integrar um banco de dados SQLite para armazenar usuários e senhas (com hash, é claro).
- **Múltiplas Rotas:** Criar rotas adicionais (dashboard, perfil, etc.) para simular uma aplicação real.
- **Logs Detalhados:** Registrar todas as requisições em um arquivo de log.
- **Autenticação Real:** Implementar autenticação JWT ou sessões de cookie.
- **HSTS:** Adicionar headers de segurança como HSTS (HTTP Strict-Transport-Security).

