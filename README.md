# Projeto 1 - Sistemas Operacionais B

### Grupo
~~~
Bruno Kitaka - 16156341

Paulo Figueiredo - 16043028

Rafael Fioramonte - 16032708

Raíssa Davinha - 15032006

Vinícius Trevisan - 16011231
~~~

## Resumo
Código desenvolvidos pelos alunos durante as aulas de Sistemas Operacionais B na PUC Campinas, lecionadas pelo Prof. Dr. Edmar Roberto Santana de Rezende. O ambiente utilizado foi uma máquina virtual com o sistema operacional Ubuntu 16.04 com seu kernel modificado para adequação à máquina virtual.

### Introdução
Este projeto deverá permitir ao aluno familiarizar-se com os detalhes de implementação de um módulo de kernel que faz uso da API criptográfica do kernel Linux. Espera-se que ao final do projeto, cada aluno seja capaz de implementar, compilar, instalar e testar um novo módulo de kernel que realize as funções de cifrar, decifrar e calcular o resumo critpográfico (hash) dos dados fornecidos pelo usuário.

### Descrição do Projeto

O projeto consiste na implementação de um módulo de kernel capaz de cifrar, decifrar e calcular resumo critpográfico (hash) dos dados fornecidos pelo usuário. Além do módulo de kernel, também deve ser implementado um programa em espaço de usuário para testar o módulo desenvolvido.

O módulo de kernel desenvolvido deve possuir a função de um driver de dispositivo criptográfico (crypto device driver) capaz de receber requisições e enviar respostas através do arquivo de dispositivo */dev/crypto*.

Ao carregar o módulo de kernel, deve-se informar no parâmetro *key* a chave simétrica que será usada para cifrar e decifrar os dados. A chave simétrica corresponde a uma string representada em hexadecimal (cada byte corresponde a dois dígitos hexa). A carga do módulo deve ser executada como no exemplo a seguir:
~~~
insmod cryptomodule.ko key=”0123456789ABCDEF”
~~~
O envio de requisições ao dispositivo criptográfico deve ser realizado através de operações de escrita no arquivo de dispositivo. As requisições ao dispositivo devem ser realizadas no seguinte formato:
~~~
operação dados
~~~
onde:

**operação:** corresponde a um caracter que define qual operação será realizada pelo dispositivo, sendo permitidas as operações de cifrar (*c*), decifrar (*d*) ou calcular o resumo criptográfico (*h*);

**dados:** corresponde a uma string contendo os dados sobre os quais a operação será realizada representados em hexadecimal (cada byte corresponde a dois dígitos hexa).

O envio da resposta do dispositivo criptográfico contendo o resultado da operação solicitada deve ser realizado através de operações de leitura no arquivo de dispositivo. Para a operação de cifrar (*c*), a resposta deve ser uma string correspondendo aos dados fornecidos durante a requisição, cifrados com o algoritmo AES em modo ECB utilizando-se a chave fornecida durante a carga do módulo, representados em hexadecimal (cada byte corresponde a dois dígitos hexa).

Para a operação de decifrar (*d*), a resposta deve ser uma string correspondendo aos dados fornecidos durante a requisição representados em hexadecimal (cada byte corresponde a dois dígitos hexa), decifrados com o algoritmo AES em modo ECB utilizando-se a chave fornecida durante a carga do módulo.

Para a operação de cálculo de resumo criptográfico (*h*), a resposta deve ser uma string correspondendo ao resumo criptográfico em hexadecimal dos dados fornecidos durante a requisição, utilizando-se o algoritmo SHA256.

Para testar o correto funcionamento do driver de dispositivo criptográfico, deve ser implementado um programa em espaço de usuário que permita abrir o arquivo de dispositivo, enviar uma requisição fornecida pelo usuário (através de uma operação de escrita no arquivo de dispositivo) e exibir a resposta fornecida pelo dispositivo criptográfico (através de uma operação de leitura no arquivo de dispositivo).

Tanto o módulo de kernel quanto o programa de usuário devem ser compilados através de um Makefile.
