/* Projeto 1 - Modulo criptografico do kernel - Teste Usuario Read e Write
 *  Bruno Kitaka        - 16156341
 *  Paulo Figueiredo    - 16043028
 *  Rafael Fioramonte   - 16032708
 *  Raissa Davinha      - 15032006
 *  Vinícius Trevisan   - 16011231
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#define clear() printf("\033[H\033[J")

#define BUFFER_LENGTH (256/4) * 5               /* Tamanho maximo da mensagem considerada (pode ser maior, porem serao considerados os BUFFER_LENGTH primeiros bytes) */
static char mensagemRecebida[500];    /* Contem a mensagem recebida do modulo de kernel */

int main()
{
   int retorno, arquivo, opcao,entrada;
   char mensagemEnviada[500];
   char mensagemHexa[500];
   int i,j;

   clear();
   printf("Teste cryptoModule Projeto 1\n");
   arquivo = open("/dev/crypto", O_RDWR);      /* Realiza a abertura do arquivo do modulo e salva o file descriptor em arquivo */
   if (arquivo < 0)
   {
      perror("Erro ao abrir o arquivo crypto");
      return errno;
   }

  do
  {
     printf("Deseja entrar dados em: caracteres (0) ou representacao hexadecimal (1) ?: ");
     scanf("%i", &entrada);
     getchar();
     printf("Digite a string de entrada que deseja escrever no arquivo do modulo (Estrutura: c|d|h string/hexa): ");
     scanf("%[^\n]%*c", mensagemEnviada);
     memset(mensagemHexa,0,300);
     /* O programa em usuario converte a string para hexa */
     mensagemHexa[0] = mensagemEnviada[0]; /* Copia a operacao */
     mensagemHexa[1] = mensagemEnviada[1]; /* Copia o espaco apos a operacao */

     /* Converte os dados em caracteres para hexa */
     if(entrada == 0)
     {
         for (i = 2,j=2; i < strlen(mensagemEnviada); i++, j+=2)
           sprintf(&mensagemHexa[j], "%02hhx", (unsigned char)mensagemEnviada[i]);
         mensagemHexa[j]='\0';
     }
     else
     {
       strcpy(mensagemHexa,mensagemEnviada);
     }
     /* Imprime os caracteres para debug da mesma forma em que foram convertidos */
     printf("Escrevendo no dispositivo a mensagem: ");
     if(entrada == 0)
     {
       for (i = 2; i < strlen(mensagemEnviada); i++)
          printf("%02hhx ", (unsigned char)mensagemEnviada[i]);
       printf("\n");
     }
     else
     {
       printf("%s\n",mensagemHexa);
     }

     retorno = write(arquivo, mensagemHexa, strlen(mensagemHexa));  /* Enviando a string para o modulo criptografico */
     if (retorno < 0)
     {
        perror("Falha ao escrever a mensagem no dispositivo crypto");
        return errno;
     }

     printf("Pressione ENTER|RETURN para ler de volta do disposivivo crypto\n");
     getchar();

     retorno = read(arquivo, mensagemRecebida, 320);        // Read the response from the LKM
     if (retorno < 0)
     {
        perror("Falha ao ler a mensagem do dispositivo crypto");
        return errno;
     }
     printf("A mensagem recebida eh [%s]\n", mensagemRecebida);

     printf("Continuar? (0 - Nao | 1 - Sim): ");
     scanf("%i",&opcao);
     getchar();
     clear();

  } while(opcao != 0);

  close(arquivo);
  printf("Fim do programa de testes\n");
  return 0;
}
