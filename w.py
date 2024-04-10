import hashlib
import base58

def hex_to_wif_uncompressed(private_key_hex):
    # Adiciona o prefixo '80' para o formato WIF não comprimido
    extended_key = '80' + private_key_hex
    # Calcula o checksum
    checksum = hashlib.sha256(hashlib.sha256(bytes.fromhex(extended_key)).digest()).digest()[:4]
    # Adiciona o checksum no final
    extended_key += checksum.hex()
    # Codifica em Base58
    wif_uncompressed = base58.b58encode(bytes.fromhex(extended_key))
    return wif_uncompressed.decode()

def hex_to_wif_compressed(private_key_hex):
    # Adiciona o prefixo '80' para o formato WIF comprimido
    extended_key = '80' + private_key_hex + '01'
    # Calcula o checksum
    checksum = hashlib.sha256(hashlib.sha256(bytes.fromhex(extended_key)).digest()).digest()[:4]
    # Adiciona o checksum no final
    extended_key += checksum.hex()
    # Codifica em Base58
    wif_compressed = base58.b58encode(bytes.fromhex(extended_key))
    return wif_compressed.decode()

# Solicita a entrada do usuário para a chave privada hexadecimal
private_key_hex = input("Digite a chave privada em formato hexadecimal: ")

# Converte para WIF não comprimido e comprimido
wif_uncompressed = hex_to_wif_uncompressed(private_key_hex)
wif_compressed = hex_to_wif_compressed(private_key_hex)

# Exibe os resultados
print("WIF(c):", wif_compressed)
print("WIF(u):", wif_uncompressed)

