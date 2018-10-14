/* Projeto 1 - Modulo criptografico do kernel
 *  Bruno Kitaka        - 16156341
 *  Paulo Figueiredo    - 16043028
 *  Rafael Fioramonte   - 16032708
 *  Raissa Davinha      - 15032006
 *  Vinícius Trevisan   - 16011231
 */

#include <linux/init.h>        /* Macros Utilizadas para iniciar (__init) e terminar (__exit) o modulo */
#include <linux/module.h>      /* Biblioteca para carregar o modulo de kernel no sistema */
#include <linux/device.h>      /* Biblioteca para suportar o modulo de dispositivo */
#include <linux/kernel.h>      /* Contem as funcoes macros e tipos de estruturas do kernel */
#include <linux/moduleparam.h> /* Contem a funcao para receber parametros durante a inicializacao do modulo */
#include <linux/stat.h>
#include <linux/string.h>         /* Biblioteca para manipular strings em nivel de kernel */
#include <linux/fs.h>             /* Biblioteca para gerenciamento de sistema de arquivos (abrir,fechar, ler e escrever em arquivo) */
#include <linux/uaccess.h>        /* Necessario para copiar os dados para o espaco de usuario*/
#define DEVICE_NAME "crypto"      /* Nome do dispositivo que aparecera em /proc/devices (sera o nome do arquivo criado com mknode /dev/crypto c MAJOR 0) */
#define CLASS_NAME "cryptomodule" /* Definicao da classe do dispositivo */
#define KEY_SIZE 256

MODULE_LICENSE("GPL");                                               /* Tipo da licenca */
MODULE_AUTHOR("Projeto 1");                                          /* Autor */
MODULE_DESCRIPTION("Custom crypto driver - Encrypt, Decrypt, Hash"); /* Descricao do modulo */
MODULE_VERSION("1.0");                                               /* Varsao */

/* OBS: os prints estarao em /var/log/kernel.log ou dmesg
 * para imprimir tail kern.log
*/

/* Todas as variaveis globais devem ser ESTATICAS para evitar conflitos com as demais existentes na memoria do Kernel */
static int qtdBlocos;
static int majorNumber;                                 /* Armazena o numero major definido automaticamente pelo driver */
static int size_of_message;                             /* Guarda o tamanho da entrada quando o usuario grava alguma coisa no arquivo do modulo */
static char operacao;                                   /* Indica a operacao a ser realizada c - d - h */
static char *key;                                       /* Armazena a chave em CARACTERES passada como parametro na insercao do modulo -- Durante a conversao, o limite definido foi de 64 caracteres hexa de entrada ou seja, 32 bytes*/
static char keyHexa[KEY_SIZE / 8];                      /* Armazena a chave HEXADECIMAL convertida a partir da chave em CARACTERES */
static char keyChar[KEY_SIZE / 4 + 1];                  /* Representacao em caracteres da chave considerada em hexadecimal */
static char mensagemHexaInput[(KEY_SIZE / 8) * 5 + 1];  /* Armazena a mensagem lida do arquivo do modulo em forma hexadecimal para ser utilizado na criptografia, descriptografia ou hash obs: vezes 5 pois definimos que iremos realizar as operacoes com no maximo 5 blocos (160 bytes)*/
static char mensagemHexaOutput[(KEY_SIZE / 8) * 5 + 1]; /* Armazena o resultado da criptogragia, descriptografia ou hash em hexadecimal */
static char mensagemCharInput[(KEY_SIZE / 4) * 5 + 1];  /* Armazena a mensagem em CARACTERES lida do arquivo do modulo. Obs: o tamanho eh "ilimitado", mas iremos considerar os primeiros 64*5(blocos) caracteres*/
static char mensagemCharOutput[(KEY_SIZE / 4) * 5 + 1]; /* Armazena o resultado da criptogragia, descriptografia ou hash em CARACTERES, para imprimir no arquivo do modulo */
static int numUtil = 0;                                 /* Contador do numero de vezes que o arquivo de dispositivo foi aberto */
static struct device *cryptomoduleDevice = NULL;        /* Ponteiro para a struct do driver de dispositivo */
static struct class *cryptomoduleClass = NULL;          /* Ponteiro para a struct da classe representando o driver de dispositivo */

/* Prototipos das funcoes */
static int dev_abrir(struct inode *, struct file *);
static int dev_fechar(struct inode *, struct file *);
static ssize_t dev_leitura(struct file *, char *, size_t, loff_t *);
static ssize_t dev_escrita(struct file *, const char *, size_t, loff_t *);
static void converterChar2Hexa(char *pChar, char *pHexa, int qtdBlocos);
static void converterHexa2Char(char *pHexa, char *pChar, int qtdBlocos);

/* Obtendo os parametros passados na inicializacao */
/* para carregar o modulo: insmod cryptomodule.ko key="ABCDEF12345667890" */
module_param(key, charp, 0000);
MODULE_PARM_DESC(key, "Chave recebida durante o carregamento");

/* Associacao de funcoes as operacoes de abertura, fechamento, leitura e escrita em um arquivo atraves da
 * estrutura de operacoes file_operations
 */
static struct file_operations fops =
    {
        .open = dev_abrir,
        .read = dev_leitura,
        .write = dev_escrita,
        .release = dev_fechar,
        .owner = THIS_MODULE,
};

/* Funcao para inicializar/carregar o modulo de kernel utilizando a macro __init
 * O argumento static eh utilizado para limitar a visualizacao da funcao a apenas esse codigo
 * Retorna 0 caso sucesso ou um numero negativo caso contrario
 */
static int __init cryptomodule_init(void)
{
  pr_info("cryptoModule: Inicializando o modulo\n"); /* Imprimindo a menssagem somente quando o modulo for carregado (insmod) */

  /* Aqui um numero MAJOR eh definido dinamicamente, conforme sua disponibilidade */
  majorNumber = register_chrdev(0, DEVICE_NAME, &fops);
  /* Se o major for menor do que zero, indica que ocorreu uma falha ao registrar o numero */
  if (majorNumber < 0)
  {
    printk(KERN_ALERT "cryptoModule: Falha ao registrar o Major Number\n");
    return majorNumber;
  }
  pr_info("cryptoModule: Registro relizado com sucesso, o Major Number eh %d\n", majorNumber); /* Imprime o Major Number a fim de conseguir, em uma proxima etapa, criar o respectivo arquivo do dispositivo*/

  /* Registrando a classe do dispositivo */
  cryptomoduleClass = class_create(THIS_MODULE, CLASS_NAME);
  if (IS_ERR(cryptomoduleClass)) /* Checa possiveis erros e, caso existam, os remove */
  {
    unregister_chrdev(majorNumber, DEVICE_NAME);
    printk(KERN_ALERT "cryptoModule: Falha ao registrar a classe do dispositivo\n");
    return PTR_ERR(cryptomoduleClass); /* Retornando o erro em um ponteiro (cryptomoduleClass) */
  }
  pr_info("cryptoModule: A classe do dispositivo foi registrada com sucesso\n");

  /* Registrando o dispositivo, ou seja, criando o arquivo que representa o dispositivo sem ter que manualmente utilizar mknode */
  cryptomoduleDevice = device_create(cryptomoduleClass, NULL, MKDEV(majorNumber, 0), NULL, DEVICE_NAME);
  if (IS_ERR(cryptomoduleDevice))
  { /* Checa possiveis erros e, caso existam, os remove */
    class_destroy(cryptomoduleClass);
    unregister_chrdev(majorNumber, DEVICE_NAME);
    printk(KERN_ALERT "cryptoModule: Falha ao criar o dispositivo\n");
    return PTR_ERR(cryptomoduleDevice);
  }
  /* Finalmente o dispositivo foi iniciado */
  pr_info("cryptoModule: Dispositivo criado com sucesso\n");

  pr_info("cryptoModule: Chave (Key) BRUTA recebida: %s\n", key);
  converterChar2Hexa(key, keyHexa, 1);     /* Salva em keyHexa a sequencia de bytes que representa os caracteres em hexadecimal lidos no carregamento do modulo */
  converterHexa2Char(keyHexa, keyChar, 1); /* Salva em keyChar os caracteres que representam a chave em hexadecimal */
  pr_info("cryptoModule: Chave (Key) CONSIDERADA em hexadecimal: %s\n", keyChar);

  return 0; /* Retorno igual a 0 (sucesso) */
}

/* Funcao para descarregar o modulo de kernel utilizando a macro __exit
 * A ideia da utilizacao do static eh a mesma da anterior
 * Essa funcao nao possui retorno
 */
static void __exit cryptomodule_exit(void)
{
  device_destroy(cryptomoduleClass, MKDEV(majorNumber, 0)); // Destroi/Remove o dispositivo
  class_unregister(cryptomoduleClass);                      // Remove o registro da Classe anteriormente criada
  class_destroy(cryptomoduleClass);                         // Remove a classe do dispositivo
  unregister_chrdev(majorNumber, DEVICE_NAME);              // Remove o registro do Major utilizado, permitindo que demais drivers agora o utilizem
  pr_info("cryptoModule: Descarregando o modulo criptografico\n");
}

/* Essa funcao de abrir eh chamada toda vez que a operacao fopen por realizada no arquivo que representa o dispositivo
 * Ela somente incrementa o contador de quantas vezes o arquivo foi aberto
 */
static int dev_abrir(struct inode *inodep, struct file *filep)
{
  numUtil++;
  pr_info("cryptoModule: O arquivo do dipositivo foi utilizado %d vezes\n", numUtil);
  return 0;
}

/* Essa funcao eh chamada toda vez que uma leitura ocorre em espaco de usuario. O dado eh enviado do arquivo do Dispositivo
 * para o usuario, dessa forma, eh necessario copiar informacoes em espaco kernel para o espaco do usuario, dai a utilizacao da Funcao
 * copy_to_user().
 * Parametros:
 *    filep:  Representa um ponteiro de arquivo
 *    buffer: Ponteiro para o buffer em espaco de usuario onde os dados serao escritos
 *    len:    Tamanho do buffer
 *    offset: Offset, caso necessario
 */
static ssize_t dev_leitura(struct file *filep, char *buffer, size_t len, loff_t *offset)
{
  int contador_erro = 0;

  if (operacao == 'h')
    qtdBlocos = 1;
  /* ENQUANTO AS FUNCOES NAO ESTAO IMPLEMENTADAS: TESTE */
  int i;
  memcpy(mensagemHexaOutput, mensagemHexaInput, 160);

  /* Para enviar os dados para o usuario, temos que converter os dados em hexadecimal mensagemHexaOutput para mensagemCharOutput */
  /* Para isso */
  converterHexa2Char(mensagemHexaOutput, mensagemCharOutput, qtdBlocos);

  /* A funcao copy_to_user retorna 0 quando eh sucedida, sua estrutura eh:
    * copy_to_user(ponteiro para onde, ponteiro de onde, tamanho em bytes)
    */
  printk("qtdBlocos=%i  --6 end %i\n", qtdBlocos, ((5 - qtdBlocos) * 64));
  mensagemCharOutput[(qtdBlocos * 64)] = '\0';
  contador_erro = copy_to_user(buffer, mensagemCharOutput, 64 * qtdBlocos + 1); /* estou copiando para buffer size_of_message bytes de message */

  if (contador_erro == 0) /* Entrara nesse if caso a copia seja efetuada com sucesso */
  {
    printk(KERN_INFO "cryptoModule: Mensagem de saida: %s\n", mensagemCharOutput);
    return 0;
  }
  else
  {
    printk(KERN_INFO "cryptoModule: Falha ao escrever em espaco de usuario\n");
    return -EFAULT;
  }
}

/** @brief This function is called whenever the device is being written to from user space i.e.
 *  data is sent to the device from the user. The data is copied to the message[] array in this
 *  LKM using the sprintf() function along with the length of the string.
 *  @param filep A pointer to a file object
 *  @param buffer The buffer to that contains the string to write to the device
 *  @param len The length of the array of data that is being passed in the const char buffer
 *  @param offset The offset if required
 */
static ssize_t dev_escrita(struct file *filep, const char *buffer, size_t len, loff_t *offset)
{
  sprintf(&operacao, "%c", buffer[0]); // Pega a opcao de operacao
  size_of_message = len - 2;           // Armazena o tamanho da chave recebida

  /* mensagemCharInput nao pode ser maior do que 64*5 caracteres, caso for, somente consideramos os 64*5 caracteres iniciais */
  if (size_of_message > 64 * 5)
    size_of_message = 64 * 5;
  snprintf(mensagemCharInput, size_of_message + 1, "%s", buffer + 2); // buffer + 2 para nao pegar o caractere de operacao (+1 elimina o caractere de controle +1 elimina o espaco)
  printk(KERN_INFO "cryptoModule: Recebeu do arquivo a operacao:%c e dado:%s\n", operacao, mensagemCharInput);

  /* Convertendo o dado de entrada para hexa - Definimos no maximo 5 blocos de dados */
  /* Quebrando a mensagemCharInput em blocos de 32 bytes */
  /* Convertendo cada bloco de 64 caracteres para um de 32 bytes hexadecimal mensagemCharInput (64B) -> mensagemHexaInput(32B) */
  qtdBlocos = size_of_message / 64;
  if (size_of_message % 64 != 0)
    qtdBlocos += 1;

  converterChar2Hexa(mensagemCharInput, mensagemHexaInput, qtdBlocos); /* bloco menos significativo (0 1 2 3 4) */
  converterHexa2Char(mensagemHexaInput, mensagemCharOutput, qtdBlocos);

  printk(KERN_INFO "cryptoModule: Recebeu do arquivo a operacao:%c e dado convertido para Hexa: %s", operacao, mensagemCharOutput);

  /* Para as operacoes, a entrada sera a mensagemHexaInput e a saida devera obrigatoriamente estar contida em mensagemHexaOutput */
  switch (operacao)
  {
  case 'c': /* Aqui eh o codigo responsavel por Cifrar mensagemHexaInput e salvar os dados em mensagemHexaOutput */
    printk("cryptoModule: Cifrar\n");
    break;

  case 'd': /* Aqui eh o codigo responsavel por Decifrar mensagemHexaInput e salvar o resultado em mensagemHexaOutput */
    printk("cryptoModule: Decifrar\n");
    break;

  case 'h': /* Aqui eh o codigo responsavel por Calcular o hash da mensagemHexaInput e salvar em mensagemHexaOutput*/
    /* em tese, um hash nao possui limite de entrada, porem, nesse modulo, ela foi limitada a 64*5=320 caracteres */
    size_of_message = 64; /* A saida do hash eh sempre de mesmo tamanho */
    printk("cryptoModule: Calcular Hash\n");
    break;

  default:
    printk("cryptoModule: Erro, Operacao invalida\n");
    break;
  }
  return len;
}

/* Essa rotina eh chamada toda vez que o arquivo do dispositivo eh fechado (cloded) pelo programa em espaco de usuario
 * Parametros:
 *     inodep: Ponteiro para o inode do arquivo
 *     filep:  Ponteiro para o arquivo do dispositivo
 */
static int dev_fechar(struct inode *inodep, struct file *filep)
{
  pr_info("cryptoModule: Arquivo do dispositivo fechado com sucesso\n");
  return 0;
}

/* Funcao para converter um array de caracteres para um array em hexadecimal */
static void converterChar2Hexa(char *pChar, char *pHexa, int qtdBlocos)
{
  /* Ideia: caso o numero for entre 0 e 9 subtrair 48, caso for de A a F subtrair 65. Logo, realizar um OR & com o byte, shift para a direita 4x e adicionar o segundo numero */
  memset(pHexa, 0, (KEY_SIZE / 8) * qtdBlocos);                                                                                                   /* Zerando o conteudo da memoria do array keyHexa -> Garante que nao existira lixo na memoria */
  int lengthChave = ((strlen(pChar) >= (KEY_SIZE / 4) * qtdBlocos) ? (lengthChave = (KEY_SIZE / 4) * qtdBlocos) : (lengthChave = strlen(pChar))); /* Variavel para armazenar a qtd de caracteres na chave. Caso tenha mais de 64 soh os 64 primeiros sao considerados */
  int j = 32 * qtdBlocos - ((lengthChave % 2 == 0) ? (lengthChave / 2) : ((lengthChave / 2) + 1));                                                /* indice para acessar o vetor keyHexa a partir da posicao inicial correta*/
  int i = 0;                                                                                                                                      /* indice para acessar a chave de caractere lida na insercao do modulo */
  /* A fim de normalizar o numero, caso a quantidade de caracteres for impar, o primeiro caractere da chave devera ocupar o primeiro byte de keyHexa sozinho */
  if (lengthChave % 2 != 0) /* ou seja, o numero de caracteres eh impar */
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

    /* Como a quantidade de caracteres eh impar e o primeiro caractere foi salvo em um bit isolado, devemos incrementar os contadores */
    i++; /* incrementa o contador de caracteres da chave */
    j++; /* incrementa uma posicao de keyHexa, ja que o promeiro caractere tem q estar sozinho no byte */
  }

  /* Continuando a conversao do numero caso a quantidade de caracteres for impar ou iniciando a conversao caso a quantidade de caracteres for par */
  for (i; ((i < lengthChave) && i < ((KEY_SIZE / 4) * qtdBlocos)); i++) /* o indice i vai de 0 a 63 no maximo, ou seja, caso a chave for maior que 64 caracteres, soh pega os 64 primeiros */
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
    /* Definindo quando ocorre o shift no byte para armazenar o segundo numero no mesmo byte */
    if (lengthChave % 2 != 0) /* Caso a quantidade de caracteres for IMPAR */
    {
      if (i % 2 != 0) /* O shift de 4 posicoes ocorrera quando o indice i, ou seja, o apontador para a chave em caracteres for IMPAR */
      {
        pHexa[j] = pHexa[j] << 4;
      }
      else /* Caso o contador da posicao do vetor de caracteres nao for impar, ou seja, ja cadastramos o segundo digito ...*/
      {
        j++; /*... pula para o proximo byte de keyHexa */
      }
    }
    else /* Caso a quantidade de caracteres for PAR */
    {
      if (i % 2 == 0) /* O shift de 4 posicoes para a direita ocorrera quando o indice i for PAR */
      {
        pHexa[j] = pHexa[j] << 4;
      }
      else /* Caso o contador de posicao do vetor de caracteres NAO FOR PAR, ou seja, ja cadastramos o segundo digito ... */
      {
        j++; /*... pula para o proximo byte de keyHexa */
      }
    }
  }
}

/* Funcao para converter um array de hexadecimais para uma string de caracteres */
static void converterHexa2Char(char *pHexa, char *pChar, int qtdBlocos)
{
  int i;
  memset(pChar, 0, (KEY_SIZE / 4) * qtdBlocos); /* Zerando o conteudo da memoria do array keyHexa -> Garante que nao existira lixo na memoria */
  for (i = 0; i < (KEY_SIZE / 8) * qtdBlocos; i++)
    sprintf(&pChar[i * 2], "%02x", (unsigned char)pHexa[i]);
  pChar[(KEY_SIZE / 4) * qtdBlocos] = '\0';
}

/* Inicializacao das funcoes de init e exit, ja que ambas foram criadas com macros */
module_init(cryptomodule_init);
module_exit(cryptomodule_exit);
