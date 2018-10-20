#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define KEY_SIZE 256
void main()
{
  /* Tem que receber a chave com simple_strtol e adicionar um espaco a cada 8 caracteres */
  char pChar[] = {"ABCDEF012301"};
  char pHexa[32],pChar2[64];
  int size_of_message = strlen (pChar);

 /* Ideia: caso o numero for entre 0 e 9 subtrair 48, caso for de A a F subtrair 65. Logo, realizar um OR & com o byte, shift para a direita 4x e adicionar o segundo numero */
 int i;
 int j=0;
 memset(pHexa, 0, (KEY_SIZE / 8));      /* Seta todas as posicoes com 0 -- size_of_messagesera OBRIGATORIAMENTE PAR, ja que cada digito hexa correspondem a dois numeros */                                                                                             /* Zerando o conteudo da memoria do array keyHexa -> Garante que nao existira lixo na memoria */

 printf("size:%i\n",size_of_message);

 for(i=0; i<size_of_message;i++)
 {
   if (pChar[i] >= 48 && pChar[i] <= 57) /* o caractere da chave eh entre 0(ASCII 48) e 9(ASCII 57) */
   {
     pHexa[j] = pHexa[j] | (pChar[i] - 48); /* Subtrai 48 para obter o valor do caractere em seu numero correspondente e manipula os bits com OR*/
   }
   else if (pChar[i] >= 97 && pChar[i] <= 102) /* o caractere da chave eh entre a(ASCII 97) e f(ASCII 102) */
   {
     pHexa[j] = pHexa[j] | (pChar[i] - 87); /* Subtrai 87 para obter o valor do caractere em seu numero correspondente (entre 10 e 15) e manipula os bits com OR*/
   }
   else /* o caractere da chave eh entre A(ASCII 65) e F(ASCII 70) */
   {
     pHexa[j] = pHexa[j] | (pChar[i] - 55); /* Subtrai 55 para obter o valor do caractere em seu numero correspondente (entre 10 e 15) e manipula os bits com OR*/
   }

   if (i % 2 == 0) /* O shift de 4 posicoes ocorrera quando o indice i, ou seja, o apontador para a chave em caracteres for PAR */
   {
     pHexa[j] = pHexa[j] << 4;
   }
   else /* Caso o contador da posicao do vetor de caracteres nao for par, ou seja, ja cadastramos o segundo digito ...*/
   {
     j++; /*... pula para o proximo byte de keyHexa */
   }
 }
 pHexa[j+1]='\0';


 memset(pChar2, 0, (KEY_SIZE / 4)); /* Zerando o conteudo da memoria do array keyHexa -> Garante que nao existira lixo na memoria */
 for (i = 0; i < size_of_message/2; i++)
 {
   printf("i=%i \n",i);
   sprintf(&pChar2[i * 2], "%02hhx", (unsigned char)pHexa[i]);

 }
 pChar2[i*2] = '\0';
 printf("%s\n",pChar2);
 printf("****\n");

}
