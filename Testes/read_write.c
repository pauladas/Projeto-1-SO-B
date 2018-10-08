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
static char mensagemRecebida[BUFFER_LENGTH];    /* Contem a mensagem recebida do modulo de kernel */

int main()
{
   int retorno, arquivo, opcao;
   char mensagemEnviada[BUFFER_LENGTH];

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
     printf("Digite a string de entrada que deseja escrever no arquivo do modulo (Estrutura: c|d|h ABCDEFG0123456789...)\n");
     scanf("%[^\n]%*c", mensagemEnviada);
     printf("Escrevendo no dispositivo a mensagem [%s].\n", mensagemEnviada);

     retorno = write(arquivo, mensagemEnviada, strlen(mensagemEnviada));  /* Enviando a string para o modulo criptografico */
     if (retorno < 0)
     {
        perror("Falha ao escrever a mensagem no dispositivo crypto");
        return errno;
     }

     printf("Pressione ENTER|RETURN para ler de volta do disposivivo crypto\n");
     getchar();

     retorno = read(arquivo, mensagemRecebida, BUFFER_LENGTH);        // Read the response from the LKM
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
