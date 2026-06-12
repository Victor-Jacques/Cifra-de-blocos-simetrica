import struct
import sys
import os
import getpass

# =============================================
# CONSTANTES
# =============================================

NUM_RODADAS = 4

# Razão áurea (φ) escalada para 32 bits: 2³² / 1.618... ≈ 2654435769
# Usada em hash e criptografia (TEA, SHA-1) por distribuir bits sem padrões repetitivos
CONST_AUREA = 0x9E3779B9

# Primeiros 32 bits da constante FNV (Fowler–Noll–Vo), usada em funções de hash
# Tem boa distribuição de bits, ideal para mistura de chaves
CONST_FNV = 0x6C62272E

# Parâmetros do gerador congruencial linear do padrão ANSI C (mesmos da função rand())
# Geram sequências pseudo-aleatórias com boa distribuição
CONST_LCG_MULT = 0x41C64E6D
CONST_LCG_ADD  = 0x3039

# Constantes arbitrárias tradicionais usadas para diferenciar os seeds
# da S-Box e da permutação, evitando que gerem a mesma sequência
CONST_DEAD = 0xDEADBEEF      # seed extra na derivação de subchaves
CONST_CAFE = 0xCAFEBABE      # seed extra na geração da permutação
CONST_LCG_ADD_PERM = 0x6073  # variação do addend do LCG usada só na permutação

# Magic number embutido nos dados ANTES de encriptar
# Se a senha for errada na decriptação, esse valor não vai aparecer → senha inválida
# 0x494E4E53 = "INNS" em ASCII (Inn Seguros)
MAGIC = 0x494E4E53

# =============================================
# DERIVAÇÃO DE CHAVES
# =============================================

def string_para_chave(senha: str) -> int:
    """Converte a string fornecida pelo usuário em uma chave mestre de 32 bits."""
    h = 0x12345678
    for ch in senha:
        h ^= ord(ch)
        h = ((h << 5) | (h >> 27)) & 0xFFFFFFFF  # rotação de 5 bits à esquerda
        h = (h * CONST_AUREA) & 0xFFFFFFFF        # multiplicação pela razão áurea
    return h

def gerar_subchaves(chave_mestre: int, num_rodadas: int) -> list:
    """Deriva uma subchave de 32 bits diferente para cada rodada."""
    subchaves = []
    k = chave_mestre
    for i in range(num_rodadas):
        k ^= (i + 1) * CONST_DEAD                # mistura com constante dependente da rodada
        k = ((k << 7) | (k >> 25)) & 0xFFFFFFFF  # rotação de 7 bits à esquerda
        k = (k * CONST_FNV) & 0xFFFFFFFF          # multiplicação pela constante FNV
        subchaves.append(k)
    return subchaves

# =============================================
# S-BOX (SUBSTITUIÇÃO)
# =============================================

def gerar_sbox(subchave: int) -> list:
    """
    Gera uma S-Box de 16 entradas embaralhada com base na subchave.
    Usa o algoritmo Fisher-Yates com seed derivado da subchave,
    garantindo que a substituição seja dependente da chave.
    """
    sbox = list(range(16))
    seed = subchave
    for i in range(15, 0, -1):
        seed = (seed * CONST_LCG_MULT + CONST_LCG_ADD) & 0xFFFFFFFF  # LCG padrão ANSI C
        j = seed % (i + 1)
        sbox[i], sbox[j] = sbox[j], sbox[i]
    return sbox

def aplicar_substituicao(bloco: int, sbox: list) -> int:
    """
    Substitui cada nibble (4 bits) do bloco de 32 bits usando a S-Box.
    Um bloco de 32 bits possui 8 nibbles, cada um substituído independentemente.
    Garante confusão: relação complexa entre chave e texto cifrado.
    """
    resultado = 0
    for i in range(8):                          # 32 bits / 4 = 8 nibbles
        nibble = (bloco >> (i * 4)) & 0xF       # extrai nibble na posição i
        resultado |= sbox[nibble] << (i * 4)    # substitui e reposiciona
    return resultado

# =============================================
# PERMUTAÇÃO
# =============================================

def gerar_permutacao(subchave: int) -> list:
    """
    Gera uma permutação de 32 posições de bits baseada na subchave.
    Usa Fisher-Yates com seed diferente do usado na S-Box (XOR com CONST_CAFE)
    para garantir que permutação e substituição não gerem a mesma sequência.
    """
    perm = list(range(32))
    seed = subchave ^ CONST_CAFE  # seed diferente do usado na S-Box
    for i in range(31, 0, -1):
        seed = (seed * CONST_LCG_MULT + CONST_LCG_ADD_PERM) & 0xFFFFFFFF
        j = seed % (i + 1)
        perm[i], perm[j] = perm[j], perm[i]
    return perm

def aplicar_permutacao(bloco: int, perm: list) -> int:
    """
    Move cada bit do bloco para a posição definida pela permutação.
    Garante difusão: cada bit do texto claro influencia muitos bits do texto cifrado.
    """
    resultado = 0
    for i in range(32):
        bit = (bloco >> i) & 1       # extrai bit na posição i
        resultado |= bit << perm[i]  # move para nova posição
    return resultado

# =============================================
# ENCRIPTAÇÃO E DECRIPTAÇÃO DE BLOCOS
# =============================================

def encriptar_bloco(bloco: int, subchaves: list) -> int:
    """
    Encripta um bloco de 32 bits aplicando NUM_RODADAS rodadas.
    Cada rodada: XOR com subchave → substituição → permutação.
    """
    for i in range(NUM_RODADAS):
        sbox = gerar_sbox(subchaves[i])
        perm = gerar_permutacao(subchaves[i])
        bloco ^= subchaves[i]                      # AddRoundKey: XOR com subchave
        bloco = aplicar_substituicao(bloco, sbox)  # confusão
        bloco = aplicar_permutacao(bloco, perm)    # difusão
    return bloco

def decriptar_bloco(bloco: int, subchaves: list) -> int:
    """
    Decripta um bloco de 32 bits aplicando as rodadas em ordem inversa.
    Cada rodada inversa: permutação inversa → substituição inversa → XOR com subchave.
    """
    for i in range(NUM_RODADAS - 1, -1, -1):  # rodadas ao contrário
        sbox = gerar_sbox(subchaves[i])
        perm = gerar_permutacao(subchaves[i])

        # inverte a permutação
        perm_inv = [0] * 32
        for j in range(32):
            perm_inv[perm[j]] = j

        # inverte a S-Box
        sbox_inv = [0] * 16
        for j in range(16):
            sbox_inv[sbox[j]] = j

        bloco = aplicar_permutacao(bloco, perm_inv)     # desfaz difusão
        bloco = aplicar_substituicao(bloco, sbox_inv)   # desfaz confusão
        bloco ^= subchaves[i]                           # desfaz XOR com subchave
    return bloco

# =============================================
# PADDING
# =============================================

def adicionar_padding(dados: bytes) -> bytes:
    """
    Adiciona padding para garantir que os dados sejam múltiplos de 4 bytes.
    O valor de cada byte de padding é igual à quantidade de bytes adicionados.
    Se os dados já forem múltiplos de 4, adiciona um bloco extra de 4 bytes.
    """
    resto = len(dados) % 4
    if resto != 0:
        pad = 4 - resto
        dados += bytes([pad] * pad)
    else:
        dados += bytes([4] * 4)  # bloco extra para evitar ambiguidade
    return dados

# =============================================
# PROCESSAMENTO DE ARQUIVO
# =============================================

def encriptar_arquivo(entrada: str, saida: str, senha: str):
    """
    Encripta o arquivo de entrada e grava o resultado no arquivo de saída.

    Estrutura do arquivo gerado:
      [ tamanho_original (4 bytes, claro) ][ magic + dados encriptados ]

    O magic é embutido nos dados ANTES de encriptar, então só aparece
    corretamente se a senha usada na decriptação for a mesma.
    """
    chave_mestre = string_para_chave(senha)
    subchaves = gerar_subchaves(chave_mestre, NUM_RODADAS)

    with open(entrada, 'rb') as f:
        dados = f.read()

    tamanho_original = len(dados)

    # prepend do magic nos dados antes de encriptar
    # assim o magic só aparece corretamente se a senha for certa
    magic_bytes = struct.pack('>I', MAGIC)
    dados = magic_bytes + dados

    dados = adicionar_padding(dados)

    resultado = bytearray()
    for i in range(len(dados) // 4):
        bloco_bytes = dados[i*4 : i*4+4]
        bloco_int = struct.unpack('>I', bloco_bytes)[0]
        bloco_enc = encriptar_bloco(bloco_int, subchaves)
        resultado += struct.pack('>I', bloco_enc)

    with open(saida, 'wb') as f:
        # grava tamanho original em claro (não é dado sensível)
        f.write(struct.pack('>I', tamanho_original))
        f.write(resultado)

    print(f"Encriptado com sucesso. Arquivo salvo em: {saida}")

def decriptar_arquivo(entrada: str, saida: str, senha: str):
    """
    Decripta o arquivo de entrada e grava o resultado no arquivo de saída.
    Verifica o magic number após decriptar para confirmar que a senha está correta.
    """
    chave_mestre = string_para_chave(senha)
    subchaves = gerar_subchaves(chave_mestre, NUM_RODADAS)

    with open(entrada, 'rb') as f:
        header_tam = f.read(4)   # tamanho original gravado em claro
        dados      = f.read()    # conteúdo encriptado

    if len(header_tam) < 4:
        print("Erro: arquivo inválido ou corrompido.")
        sys.exit(1)

    tamanho_original = struct.unpack('>I', header_tam)[0]

    # decripta todos os blocos
    resultado = bytearray()
    for i in range(len(dados) // 4):
        bloco_bytes = dados[i*4 : i*4+4]
        bloco_int = struct.unpack('>I', bloco_bytes)[0]
        bloco_dec = decriptar_bloco(bloco_int, subchaves)
        resultado += struct.pack('>I', bloco_dec)

    # os primeiros 4 bytes decriptados devem ser o magic
    magic_lido = struct.unpack('>I', bytes(resultado[:4]))[0]
    if magic_lido != MAGIC:
        print("Erro: senha incorreta ou arquivo corrompido.")
        sys.exit(1)

    # remove o magic do início e corta pelo tamanho original
    dados_reais = bytes(resultado[4 : 4 + tamanho_original])

    with open(saida, 'wb') as f:
        f.write(dados_reais)

    print(f"Decriptado com sucesso. Arquivo salvo em: {saida}")

# =============================================
# ENTRADA POR LINHA DE COMANDO
# =============================================

def uso():
    print("Uso: python cifra.py <arquivo_entrada> <enc|dec>")
    print()
    print("  <arquivo_entrada>   Arquivo a ser processado")
    print("  <enc|dec>           enc para encriptar, dec para decriptar")
    print()
    print("Exemplos:")
    print("  python cifra.py documento.txt enc")
    print("  python cifra.py documento.enc dec")
    sys.exit(1)

if __name__ == '__main__':
    if len(sys.argv) != 3:
        uso()

    arquivo_entrada = sys.argv[1]
    modo = sys.argv[2].strip().lower()

    if modo not in ('enc', 'dec'):
        print(f"Erro: modo '{modo}' inválido. Use 'enc' ou 'dec'.")
        print()
        uso()

    if not os.path.isfile(arquivo_entrada):
        print(f"Erro: arquivo '{arquivo_entrada}' não encontrado.")
        sys.exit(1)

    # senha digitada de forma oculta, não aparece no terminal nem no histórico
    senha = getpass.getpass("Senha: ")

    if not senha:
        print("Erro: a senha não pode ser vazia.")
        sys.exit(1)

    # define nome do arquivo de saída automaticamente
    nome, ext = os.path.splitext(arquivo_entrada)

    if modo == 'enc':
        arquivo_saida = nome + '.enc'      # documento.txt → documento.enc
    else:
        if ext == '.enc':
            arquivo_saida = nome           # documento.enc → documento (nome original)
        else:
            arquivo_saida = nome + '_dec' + ext

    if modo == 'enc':
        encriptar_arquivo(arquivo_entrada, arquivo_saida, senha)
    else:
        decriptar_arquivo(arquivo_entrada, arquivo_saida, senha)