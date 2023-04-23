import magic
import hashlib

# Verifica o tipo de arquivo
def get_file_type(file_path):
    mime = magic.Magic(mime=True)
    return mime.from_file(file_path)

# Verifica se o arquivo está criptografado
def is_encrypted(file_path):
    # Verifica o tipo de arquivo
    file_type = get_file_type(file_path)
    # Hash do primeiro bloco do arquivo
    with open(file_path, 'rb') as f:
        block = f.read(1024)
        hash_value = hashlib.sha256(block).hexdigest()
    # Verifica se o arquivo é criptografado
    if file_type.startswith('application/') and hash_value not in ('8a35b343722d5b5c51e5b11ab8ca0dbf66eb02f9b3659e44c27af16db0f0be3e', '3d0c50c34bb26bfe7aa890a042d6c8fb17de36a1d49a71bfe262fb8b1cfa83e7'):
        return True
    return False

# Detecta a criptografia
def detect_encryption(file_path):
    # Verifica o tipo de arquivo
    file_type = get_file_type(file_path)
    # Verifica se o arquivo é criptografado
    if is_encrypted(file_path):
        if file_type == 'application/x-gpg-encrypted':
            return 'GPG'
        elif file_type == 'application/pkcs7-mime':
            return 'PKCS7'
        elif file_type == 'application/x-pkcs12':
            return 'PKCS12'
        # Adicione mais tipos de arquivos aqui
    return None

# Exemplo de uso
file_path = 'arquivo_criptografado.gpg'
if is_encrypted(file_path):
    encryption_type = detect_encryption(file_path)
    print(f'O arquivo está criptografado com {encryption_type}.')
else:
    print('O arquivo não está criptografado.')
