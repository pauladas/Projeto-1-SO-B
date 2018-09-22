/* Projeto 1 - Modulo criptografico do kernel
 *  Bruno Kitaka        - 16156341
 *  Paulo Figueiredo    - 16043028
 *  Rafael Fioramonte   - 16032708
 *  Raissa Davinha      - 15032006
 *  Vinícius Trevisan   - 16011231
 */

#include <linux/init.h>                                          /* Macros Utilizadas para iniciar (__init) e terminar (__exit) o modulo */
#include <linux/module.h>                                        /* Biblioteca para carregar o modulo de kernel no sistema */
#include <linux/device.h>                                        /* Biblioteca para suportar o modulo de dispositivo */
#include <linux/kernel.h>                                        /* Contem as funcoes macros e tipos de estruturas do kernel */
#include <linux/moduleparam.h>                                   /* Contem a funcao para receber parametros durante a inicializacao do modulo */
#include <linux/stat.h>
#include <linux/fs.h>                                            /* Biblioteca para gerenciamento de sistema de arquivos (abrir,fechar, ler e escrever em arquivo) */
#include <linux/uaccess.h>                                       /* Necessario para copiar os dados para o espaco de usuario*/
#define  DEVICE_NAME "crypto"                                    /* Nome do dispositivo que aparecera em /proc/devices (sera o nome do arquivo criado com mknode /dev/crypto c MAJOR 0) */
#define  CLASS_NAME  "cryptomodule"                              /* TDefinicao da classe do dispositivo */
#define  KEY_SIZE 128

MODULE_LICENSE("GPL");                                                     /* Tipo da licenca */
MODULE_AUTHOR("Projeto 1");                                                /* Autor */
MODULE_DESCRIPTION("Custom crypto driver - Encrypt, Decrypt, Hash");       /* Descricao do modulo */
MODULE_VERSION("1.0");                                                     /* Varsao */

/* OBS: os prints estarao em /var/log/kernel.log
 * para imprimir tail kern.log
*/

/* Todas as variaveis globais devem ser ESTATICAS para evitar conflitos com as demais existentes na memoria do Kernel */
static int        majorNumber;                        /* Armazena o numero major definido automaticamente pelo driver */
static char       operacao;                           /* Indica a operacao a ser realizada c - d - h */
static char       *key;                               /* Armazena a chave em caracteres passada como parametro na insercao do modulo */
static char       mensagem[KEY_SIZE/4];               /* Armazena o valor lido do arquivo do modulo */
static long       keyHexa;                            /* Armazena a chave hexadecimal convertida a partir da chave em caracteres  *******************************************/
static short      size_of_message;                    ///< Used to remember the size of the string stored                                   ************************
static int        numberOpens = 0;                    /* Contador do numero de vezes que o arquivo de dispositivo foi aberto */
static struct     device* cryptomoduleDevice = NULL;  /* Ponteiro para a struct do driver de dispositivo */
static struct     class*  cryptomoduleClass  = NULL;  /* Ponteiro para a struct da classe representando o driver de dispositivo */

/* Prototipos das funcoes */
static int     dev_abrir(struct inode *, struct file *);
static int     dev_fechar(struct inode *, struct file *);
static ssize_t dev_leitura(struct file *, char *, size_t, loff_t *);
static ssize_t dev_escrita(struct file *, const char *, size_t, loff_t *);
static void converterChaveHexa(char chave[]);
static void converterChaveChar(long long int chave);

/* Obtendo os parametros passados na inicializacao */
/* para carregar o modulo: insmod cryptomodule.ko key="ABCDEF12345667890" */
module_param(key,charp,0000);
MODULE_PARM_DESC(key,"Chave recebida durante o carregamento");

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
   pr_info("cryptoModule: Inicializando o modulo\n");                                    /* Imprimindo a menssagem somente quando o modulo for carregado (insmod) */

   /* Aqui um numero MAJOR eh definido dinamicamente, conforme sua disponibilidade */
   majorNumber = register_chrdev(0, DEVICE_NAME, &fops);
   /* Se o major for menor do que zero, indica que ocorreu uma falha ao registrar o numero */
   if (majorNumber<0)
   {
      printk(KERN_ALERT "cryptoModule: Falha ao registrar o Major Number\n");
      return majorNumber;
   }
   pr_info("cryptoModule: Registro relizado com sucesso, o Major Number eh %d\n", majorNumber);       /* Imprime o Major Number a fim de conseguir, em uma proxima etapa, criar o respectivo arquivo do dispositivo*/

   /* Registrando a classe do dispositivo */
   cryptomoduleClass = class_create(THIS_MODULE, CLASS_NAME);
   if (IS_ERR(cryptomoduleClass))                     /* Checa possiveis erros e, caso existam, os remove */
   {
      unregister_chrdev(majorNumber, DEVICE_NAME);
      printk(KERN_ALERT "cryptoModule: Falha ao registrar a classe do dispositivo\n");
      return PTR_ERR(cryptomoduleClass);              /* Retornando o erro em um ponteiro (cryptomoduleClass) */
   }
   pr_info("cryptoModule: A classe do dispositivo foi registrada com sucesso\n");

   /* Registrando o dispositivo, ou seja, criando o arquivo que representa o dispositivo sem ter que manualmente utilizar mknode */
   cryptomoduleDevice = device_create(cryptomoduleClass, NULL, MKDEV(majorNumber, 0), NULL, DEVICE_NAME);
   if (IS_ERR(cryptomoduleDevice)){                        /* Checa possiveis erros e, caso existam, os remove */
      class_destroy(cryptomoduleClass);
      unregister_chrdev(majorNumber, DEVICE_NAME);
      printk(KERN_ALERT "cryptoModule: Falha ao criar o dispositivo\n");
      return PTR_ERR(cryptomoduleDevice);
   }
   /* Finalmente o dispositivo foi iniciado */
   pr_info("cryptoModule: Dispositivo criado com sucesso\n");

   pr_info("Chave (Key) BRUTA recebida: %s\n", key);
   converterChaveHexa(key);
   pr_info("Chave (Key) CONVERTIDA em hexadecimal recebida: %x\n", keyHexa);
   // TESTE
   converterChaveChar(keyHexa);
   operacao = 'c';
   size_of_message=1;
   pr_info("Chave (Key) CONVERTIDA em caracteres recebida: %s\n", mensagem);

   return 0; /* Retorno igual a 0 (sucesso) */
}

/* Funcao para descarregar o modulo de kernel utilizando a macro __exit
 * A ideia da utilizacao do static eh a mesma da anterior
 * Essa funcao nao possui retorno
 */
static void __exit cryptomodule_exit(void)
{
   device_destroy(cryptomoduleClass, MKDEV(majorNumber, 0));    // Destroi/Remove o dispositivo
   class_unregister(cryptomoduleClass);                         // Remove o registro da Classe anteriormente criada
   class_destroy(cryptomoduleClass);                            // Remove a classe do dispositivo
   unregister_chrdev(majorNumber, DEVICE_NAME);                 // Remove o registro do Major utilizado, permitindo que demais drivers agora o utilizem
   pr_info("cryptoModule: Descarregando o modulo criptografico\n");
}

/* Essa funcao de abrir eh chamada toda vez que a operacao fopen por realizada no arquivo que representa o dispositivo
 * Ela somente incrementa o contador de quantas vezes o arquivo foi aberto
 */
static int dev_abrir(struct inode *inodep, struct file *filep)
{
   numberOpens++;
   pr_info("cryptoModule: O arquivo do dipositivo foi aberto %d vezes\n", numberOpens);
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
   // int error_count = 0;
   // /* A funcao copy_to_user retorna 0 quando eh sucedida, sua estrutura eh:
   //  * copy_to_user(ponteiro para onde, ponteiro de onde, tamanho em bytes)
   //  */
   // error_count = copy_to_user(buffer, message, size_of_message); /* estou copiando para buffer size_of_message bytes de message */
   //
   // if (error_count==0) /* Entrara nesse if caso a copia seja efetuada com sucesso */
   // {
   //    printk(KERN_INFO "cryptoModule: Enviou %d bytes para o usuario\n", size_of_message);
   //    return (size_of_message=0);  // clear the position to the start and return 0
   // }
   // else
   // {
   //    printk(KERN_INFO "EBBChar: Failed to send %d characters to the user\n", error_count);
   //    return -EFAULT;              // Failed -- return a bad address message (i.e. -14)
   // }
}

/** @brief This function is called whenever the device is being written to from user space i.e.
 *  data is sent to the device from the user. The data is copied to the message[] array in this
 *  LKM using the sprintf() function along with the length of the string.
 *  @param filep A pointer to a file object
 *  @param buffer The buffer to that contains the string to write to the device
 *  @param len The length of the array of data that is being passed in the const char buffer
 *  @param offset The offset if required
 */
static ssize_t dev_escrita(struct file *filep, const char *buffer, size_t len, loff_t *offset){
   // sprintf(message, "%s(%zu letters)", buffer, len);   // appending received string with its length
   // size_of_message = strlen(message);                 // store the length of the stored message
   // printk(KERN_INFO "EBBChar: Received %zu characters from the user\n", len);
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

/* Funcao para converter uma chave em caracteres para um valor long int em hexadecimal */
static void converterChaveHexa(char chave[])
{
  kstrtol(chave, 16, &keyHexa); /* Converte o array de caracteres em uma sequencia de bytes */
}

/* Funcao para converter um valor inteiro hexadecima; para uma string de caracteres */
static void converterChaveChar(long long int chave)
{
  snprintf(mensagem,"%x",chave);
}

/* Inicializacao das funcoes de init e exit, ja que ambas foram criadas com macros */
module_init(cryptomodule_init);
module_exit(cryptomodule_exit);
