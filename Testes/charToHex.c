#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void main()
{
  /* Tem que receber a chave com simple_strtol e adicionar um espaco a cada 8 caracteres */
  char chave[] = {"1234567890ABCDEF1234567890ABCD000001abcd"};
  char keyHexa[32] = {0};

 /* Ideia: caso o numero for entre 0 e 9 subtrair 48, caso for de A a F subtrair 65. Logo, realizar um OR & com o byte, shift para a direita 4x e adicionar o segundo numero */
 printf("Chave BRUTA recebida: %s\n", chave);
 memset(keyHexa,0,32);
 int lengthChave = ((strlen(chave)>=64) ? (lengthChave = 64):(lengthChave = strlen(chave)));
 int j=32 - ((lengthChave%2 == 0 )?(lengthChave/2):((lengthChave/2) + 1)); /* indice para acessar o vetor keyHexa a partir da posicao inicial correta*/
 int i=0;


 if(lengthChave%2 != 0) /* ou seja, o numero de caracteres eh impar */
 {
   if(chave[i] >= 48 && chave[i] <= 57) /* o numero da chave eh entre 0 e 9 */
   {
     keyHexa[j] = keyHexa[j] | (chave[i]-48);
   }
   else if(chave[i] >= 97 && chave[i] <= 102)
   {
     keyHexa[j] = keyHexa[j] | (chave[i]-87);
   }
   else /* O valor da chave eh uma letra */
   {
     keyHexa[j] = keyHexa[j] | (chave[i]-55);
   }
   i++;
   j++;
 }


 for(i; i<lengthChave && i<64; i++) /* o indice i vai de 0 a 63 no maximo */
 {
   if(chave[i] >= 48 && chave[i] <= 57) /* o numero da chave eh entre 0 e 9 */
   {
     keyHexa[j] = keyHexa[j] | (chave[i]-48);
   }
   else if(chave[i] >= 97 && chave[i] <= 102)
   {
     keyHexa[j] = keyHexa[j] | (chave[i]-87);
   }
   else /* O valor da chave eh uma letra */
   {
     keyHexa[j] = keyHexa[j] | (chave[i]-55);
   }
   if(lengthChave%2 != 0)
   {
     if(i%2 != 0)
     {
       keyHexa[j] = keyHexa[j] << 4;
     }
     else
     {
        j++;
     }
   }
   else
   {
     if(i%2 == 0)
     {
       keyHexa[j] = keyHexa[j] << 4;
     }
     else
     {
       j++;
     }
   }
 }


 char caracteres[65];
 /* Conversao da chave keyHexa em um array de caracteres legiveis para o usuario */
 printf("Chave hexadecimal convertida para CARACTERES: ");
 for(int i=0;i<32;i++) sprintf(&caracteres[i*2],"%02x",(unsigned char)keyHexa[i]);
 printf("%s\n",caracteres);
}
