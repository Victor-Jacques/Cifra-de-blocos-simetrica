# Cifra de Blocos Simétrica (INNS)

Este projeto implementa uma cifra de blocos simétrica personalizada em Python, projetada para fins educacionais e demonstração de conceitos fundamentais de criptografia, como confusão e difusão.

## 🚀 Funcionalidades

- **Cifra de Blocos de 32 bits:** Processa dados em blocos de 4 bytes.
- **Derivação de Chave Dinâmica:** Transforma uma senha textual em uma chave mestre de 32 bits e deriva subchaves exclusivas para cada rodada.
- **S-Box Dinâmica:** Gera tabelas de substituição baseadas na chave para cada rodada (Confusão).
- **Permutação de Bits Dinâmica:** Gera tabelas de permutação baseadas na chave para cada rodada (Difusão).
- **Proteção de Senha:** Utiliza a biblioteca `getpass` para garantir que a senha não seja exibida no terminal.
- **Verificação de Integridade:** Utiliza um "Magic Number" no cabeçalho para validar se o arquivo foi criptografado por este programa e se a senha fornecida tem grandes chances de estar correta.

## 🛠️ Como Funciona (Detalhes Técnicos)

A cifra opera através de múltiplas rodadas (padrão: 4), seguindo uma estrutura inspirada em cifras modernas:

1.  **Derivação de Chave:**
    - A senha é processada usando a **Razão Áurea (φ)** para distribuir os bits uniformemente.
    - As subchaves de rodada são geradas usando a constante **FNV** e operações de rotação de bits.
2.  **Confusão (Substituição):**
    - Cada bloco de 32 bits é dividido em 8 "nibbles" (4 bits cada).
    - Uma **S-Box** de 16 entradas é gerada dinamicamente via algoritmo **Fisher-Yates**, alimentada por um gerador de números pseudo-aleatórios (LCG) semeado pela subchave da rodada.
3.  **Difusão (Permutação):**
    - Os bits do bloco são reordenados conforme uma tabela de permutação também gerada dinamicamente via Fisher-Yates, garantindo que a alteração de um bit se espalhe por todo o bloco.
4.  **Padding:**
    - Utiliza um sistema de preenchimento para garantir que o arquivo seja múltiplo de 32 bits, armazenando o tamanho original no cabeçalho para uma reconstrução perfeita do arquivo original.

## 📋 Pré-requisitos

- Python 3.6 ou superior.
- Nenhuma biblioteca externa é necessária (utiliza apenas módulos padrão: `struct`, `sys`, `os`, `getpass`).

## 💻 Uso

O script é executado via linha de comando:

### Criptografar um arquivo
```bash
python cifra.py <arquivo_original> enc
```
*Exemplo:* `python cifra.py segredo.txt enc` -> Gera `segredo.enc`

### Descriptografar um arquivo
```bash
python cifra.py <arquivo_criptografado> dec
```
*Exemplo:* `python cifra.py segredo.enc dec` -> Gera `segredo.txt` (ou o nome original)

## ⚠️ Aviso de Segurança

Este projeto foi desenvolvido para **fins didáticos**. Embora implemente conceitos reais de criptografia, ele possui limitações (como o tamanho do bloco de 32 bits e o espaço de chave reduzido) que o tornam vulnerável a ataques de força bruta modernos. **Não utilize este software para proteger dados sensíveis em ambientes de produção.**

---
Desenvolvido como um exemplo prático de arquitetura de cifras de bloco.
