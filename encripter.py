from simple_term_menu import TerminalMenu
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import HMAC
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from enum import Enum

def pad(message):
    message = message + b'\x01'
    N = len(message)
    k = (16 - N%16)%16
    for i in range(k):
        message = message + b'\x00'
    return message

def unpad(message):
    i = -1
    while message[i] == 0:
        i = i - 1
    return message[:i]

class Mode(Enum):
    ENCRYPT_THEN_MAC = 0
    ENCRYPT_AND_MAC = 1
    MAC_THEN_ENCRYPT = 2


def gerar_chave(senha):
    global salt
    salt = get_random_bytes(16)
    key = PBKDF2(senha, salt, count=1000000)
    return key


def recuperar_chave(senha, sal):
    key = PBKDF2(senha, sal, count=1000000)
    return key


def gerar_mac(dados, chave):
    return HMAC.new(key=chave, msg=dados, digestmod=SHA256).digest()


def encriptar(dados, chave, modo):
    global salt
    dados = dados.encode("utf-8")
    cipher = AES.new(key=chave, mode=AES.MODE_CBC, iv=salt)

    if modo == Mode.ENCRYPT_THEN_MAC.value:
        dados = pad(dados)
        E = cipher.encrypt(dados)
        tag = gerar_mac(E, chave)
        return E + salt + tag

    elif modo == Mode.ENCRYPT_AND_MAC.value:
        dados = pad(dados)
        E = cipher.encrypt(dados)
        tag = gerar_mac(dados, chave)
        return E + salt + tag

    elif modo == Mode.MAC_THEN_ENCRYPT.value:
        tag = gerar_mac(dados, chave)
        dados = pad(dados + salt + tag)
        E = cipher.encrypt(dados)
        return E


def decriptar(dados, chave, modo):
    global salt

    cipher = AES.new(key=chave, mode=AES.MODE_CBC, iv=salt)
    if modo == Mode.ENCRYPT_THEN_MAC.value:
        E = dados.split(salt)[0]
        tag = dados.split(salt)[1]
        message = cipher.decrypt(E)
        if gerar_mac(E, chave) == tag:
            return unpad(message).decode()
        else:
            raise Exception("Tag não bate!")

    elif modo == Mode.ENCRYPT_AND_MAC.value:
        E = dados.split(salt)[0]
        tag = dados.split(salt)[1]
        message = cipher.decrypt(E)

        if gerar_mac(message, chave) == tag:
            return bytes.decode(unpad(message), errors="ignore")
        else:
            raise Exception("Tag não bate!")

    elif modo == Mode.MAC_THEN_ENCRYPT.value:
        message, tag = unpad(cipher.decrypt(dados)).split(salt)
        if gerar_mac(message, chave):
            return bytes.decode(message, errors="ignore")
        else:
            raise Exception("Tag não bate!")

def main():
    function_menu = TerminalMenu(["Encriptar", "Decriptar"], title="Chose your destiny:", )
    function_index = function_menu.show()
    global salt

    if function_index == 0:                        #encrypt
        entry_mode_menu = TerminalMenu(["Digitar", "Arquivo"], title="Modo de Entrada:", )
        input_mode = entry_mode_menu.show()
        message = ""
        if input_mode == 0:  # input do usuario
            message = input("Mensagem: ")

        elif input_mode == 1:  # arquivo
            filePath = input("Nome do arquivo: ")
            with open(filePath, "rb") as file:
                message = file.read()
                message = message.decode("utf-8", errors="ignore")

        encrypt_mode_menu = TerminalMenu(["Encrypt-then-MAC", "Encrypt-and-MAC", "MAC-then-Encrypt"],
                                         title="Modo de autenticação:")
        menu_entry_index = encrypt_mode_menu.show()
        password = input("Digite a senha de encriptação: ")
        key = gerar_chave(password)

        encrypted_text = encriptar(message, key, menu_entry_index)

        file_name = input("Nome do arquivo encriptado: ")
        with open(file_name, "wb") as out_file:
            out_file.write(encrypted_text)
        with open(file_name+".salt", "wb") as out_file:
            out_file.write(salt)

    elif function_index == 1:               #decrypt
        file_name = input("Nome do arquivo: ")
        encrypt_mode_menu = TerminalMenu(["Encrypt-then-MAC", "Encrypt-and-MAC", "MAC-then-Encrypt"],
                                         title="Modo de autenticação:")
        menu_entry_index = encrypt_mode_menu.show()
        password = input("Digite a senha: ")

        with open(file_name+".salt", "rb") as file:
            salt = file.read()

        key = recuperar_chave(password, salt)
        encrypted_file = ""
        with open(file_name, "rb") as file:
            encrypted_file = file.read()

        decrypted_file = decriptar(encrypted_file, key, menu_entry_index)

        with open(file_name + "decrypted", "w") as out_file:
            out_file.write(decrypted_file)

if __name__ == "__main__":
    main()
