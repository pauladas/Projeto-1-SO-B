# Projeto-1 Sistema Operacionais B

### Branch
~~~
Responsável por armazenar as tarefas produzidas por em ordem cronológica:
Em reunião de grupo, a parte inicialmente definida para esse membro foi a estruturação do código do driver e criação do programa de testes
Vinícius Trevisan - RA: 16011231
~~~

### 18/09/2018
~~~
Leitura do Tutorial de como desenvolver um driver para um dispositivo de caractere;
Inicio da estruturação do código responsável pelo driver (init, exit, open, close);
~~~

### 22/09/2018
~~~
Recebimento do argumento de entrada (chave);
Definição da constante com o tamanho máximo para o bloco (chave e bloco de criptografia);
[Problemas] Função para conversao da string hexadecimal para sequencia de bits (ler a chave e ler o conteudo a ser criptografado);
[Problemas] Função para conversão de sequencia de bits para string hexadecimal (gravar o resultado no arquivo). 
~~~

### 25/09/2018
~~~
Upload do código em espaço do usuário a fim de relizar um protótipo para as converções implementadas no código do kernel;
Upload do modulo de kernel com a capacidade de receber uma chave com os problemas descritos dia 22/09 arrumados;
Teste das funções de conversão no módulo, imprimindo os resultados no log do kernel dmesg.
Limitamos o tamanho da chave de entrada para 5 blocos (cada bloco possui 256 bits ou 32 bytes)
~~~

### Tarefas a Realizar: Driver
~~~
[Fazer] Funções read e write - Nesse momendo o parametro de entrada sera passado e convertido, sem nenhuma funcao de criptografia ou descriptografia, fazendo com que o modulo consiga ler e gravar em seu respectivo arquivo;
[Fazer] Switch case com as opções de criptografia (c) descriptografia (d) e hash (h);
~~~

### Tarefas a Realizar: Teste
~~~
[Fazer] Fazer programa de teste em espaço de usuário e definir uma rotina de testes;
~~~
