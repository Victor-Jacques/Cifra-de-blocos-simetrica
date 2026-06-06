import struct
import sys

# Constantes

CONST_AUREA = 0x9E3779B9 # Razão áurea escalada para 32 bits, usada em Hash e outras criptografias
CONST_FNV = 0x6C62272E # Primeiros bits da constante Fowler-Noll-Vo, usadas em funções hash

# Parâmetros do gerador congruencial linear do padrão ANSI C, geram sequências pseudo-aleatórias.
CONST_LCG_MULT = 0x41C64E6D
CONST_LCG_ADD = 0x3039

# Constantes arbitrárias tradicionais usadas para diferenciar os seeds da S-Box e da permutação
CONST_DEAD = 0xDEADBEEF
CONST_CAFE = 0xCAFEBABE
CONST_LCG_ADD_PERM = 0x6073

numero_rodadas = 4

def string_para_chave (senha: str) -> int:
    """conversão da string fornecida para chave de 32 bits"""
    h = 0x12345678
    for caracter in senha:
        h ^= ord(caracter)
        h = ((h << 5) | (h >> 27)) & 0xFFFFFFFF
        h = (h * CONST_AUREA) & 0xFFFFFFFF

    return h

def gerar_subchaves(chave_mestre: int, numero_rodadas: int) -> list:
    """Deriva uma subchave de 32 bits diferente para cada rodada"""