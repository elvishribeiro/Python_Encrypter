# Python_Encrypter
Um encriptador e decriptador simples feito em python usando a biblioteca PyCriptodome usando encriptação autenticada.

Codifica mensagens usando criptografia autenticada no modo:
  - Encrypt-then-MAC
  - Encrypt-and-MAC
  - MAC-then-Encrypt

A encriptação é feita usando criptografia AES no modo CBC. 

A chave de encriptação é um hash usando o algoritmo HMAC cuja chave é gerada a partir de uma senha informada pelo usuário e um valor de sal que é armazenado para posterior decriptação.

## Uso:
  Para usar basta rodar o programa 
  ```python3 encripter.py```
  
É possível encriptar mensagens digitadas no terminal ou arquivos de texto.

A mensagem encriptada é gravada em um arquivo de nome informado pelo usuário e o sal também é armazenado em um arquivo de mesmo nome e extensão ".salt".

Para desencriptar basta informar o nome do arquivo, método de encriptação e senha.

### Dependências:

  - [PyCryptodome](https://github.com/Legrandin/pycryptodome)
  - [simple-term-menu](https://github.com/IngoMeyer441/simple-term-menu/)
