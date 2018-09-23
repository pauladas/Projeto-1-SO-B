# Projeto-1-SO-B

## Reponsáveis
~~~
Bruno Kitaka - RA: 16156341
Paulo Jansen de Oliveira Figueiredo - RA: 16043028
~~~

## Objetivo

O objetivo desse branch é tratar de hash e criar um módulo de hash para utilização na criptografia do módulo de kernel que está sendo desenvolvido nesse projeto. Com cada branch, é possível ver atualizações e manter controle do progresso do desenvolvimento e mais informações de cada parte do módulo.

## Fundação teórica

### Pequena introdução sobre funções hash.

Uma função hash é um algoritmo que mapeia dados de comprimento variável para dados de comprimento fixo. Os valores retornados por uma função hash são chamados valores hash, códigos hash, somas hash (hash sums), checksums ou simplesmente hashes. Um uso é uma estrutura de dados chamada de tabela hash, amplamente usada em softwares de computador para consulta de dados rápida.
Funções hash aceleram consultas à tabelas ou bancos de dados por meio da detecção de registros duplicados em um arquivo grande. Um exemplo é encontrar trechos similares em sequências de DNA. Eles também são úteis em criptografia. Uma função hash criptográfica permite verificar facilmente alguns mapeamentos de dados de entrada para um valor hash fornecido, mas se os dados de entrada são desconhecidos, é deliberadamente difícil reconstruí-lo (ou alternativas equivalentes) conhecendo o valor do hash armazenado. Isto é usado para assegurar a integridade de dados transmitidos e é o bloco de construção para HMACs, que fornecem autenticação de mensagem.

### Descrição

Um hash (ou escrutínio) é uma sequência de bits geradas por um algoritmo de dispersão, em geral representada em base hexadecimal, que permite a visualização em letras e números (0 a 9 e A a F), representando um nibble cada. O conceito teórico diz que "hash é a transformação de uma grande quantidade de dados em uma pequena quantidade de informações".
Essa sequência busca identificar um arquivo ou informação unicamente. Por exemplo, uma mensagem de correio eletrônico, uma senha, uma chave criptográfica ou mesmo um arquivo. É um método para transformar dados de tal forma que o resultado seja (quase) exclusivo. Além disso, funções usadas em criptografia garantem que não é possível a partir de um valor de hash retornar à informação original.
Uma função de hash recebe um valor de um determinado tipo e retorna um código para ele. Enquanto o ideal seria gerar identificadores únicos para os valores de entrada, isso normalmente não é possível: na maioria dos casos, o contradomínio de nossa função é muito menor do que o seu domínio.

#### Algoritmos mais usados

* MD5
* SHA-1

### Aplicações
O código é calculado em função de todos os outros digítos da entrada, de forma que qualquer alteração nos demais dados geraria um novo dígito verificador, permitindo assim que perceba-se facilmente qualquer erro de digitação, como em um sistema de Internet Banking por exemplo.
Outra aplicação de hashes é o download de arquivos da Internet. Especialmente no caso de arquivos grandes, é comum que sejam disponibilizados nos sites a informação do hash do arquivo. Desta forma, após a conclusão do download, pode-se calcular o hash sobre o arquivo baixado, comparando-o com o esperado. Em caso de qualquer alteração no conteúdo do arquivo durante o download, o hash calculado será diferente do esperado, e o erro será detectado.

### Funcionamento

#### Merkle–Damgård

Uma função hash deve ser capaz de processar uma mensagem de comprimento arbitrário produzindo uma saída de comprimento fixo. Isso pode ser alcançado, através da quebra da entrada em blocos de tamanhos iguais, e operar sobre elas, em sequência, utilizando funções de compressão unidirecional. A função de compressão pode ser especialmente projetada para calcular o hash ou construída a partir de uma cifra de blocos. A função hash construída com a construção Merkle-Damgård é tão resistente a colisão quanto a sua função de compressão; qualquer colisão para a função hash total pode ser rastreada a uma colisão em uma das funções de compressão.
O último bloco processado deve ter um "preenchimento" acrescentado a seu comprimento inequivocamente (prática conhecida como padding); isso é crucial para a segurança dessa construção. Essa construção é chamada de Merkle-Damgård.
