/* Projeto 1 - Modulo criptografico do kernel
 *  Bruno Kitaka        - 16156341
 *  Paulo Figueiredo    - 16043028
 *  Rafael Fioramonte   - 16032708
 *  Raissa Davinha      - 15032006
 *  Vinícius Trevisan   - 16011231
 */

#include <linux/init.h>                /* Macros Utilizadas para iniciar (__init) e terminar (__exit) o modulo */
#include <linux/module.h>              /* Biblioteca para carregar o modulo de kernel no sistema */
#include <linux/device.h>              /* Biblioteca para suportar o modulo de dispositivo */
#include <linux/kernel.h>              /* Contem as funcoes macros e tipos de estruturas do kernel */
#include <crypto/internal/skcipher.h>  /* Biblioteca para encriptar e decriptar */
#include <linux/crypto.h>
#include <linux/vmalloc.h>
#include <linux/moduleparam.h>         /* Contem a funcao para receber parametros durante a inicializacao do modulo */
#include <linux/stat.h>
#include <crypto/internal/hash.h>      /* Utilizada para a funcao de HASH */
#include <linux/string.h>              /* Biblioteca para manipular strings em nivel de kernel */
#include <linux/fs.h>                  /* Biblioteca para gerenciamento de sistema de arquivos (abrir,fechar, ler e escrever em arquivo) */
#include <linux/uaccess.h>             /* Necessario para copiar os dados para o espaco de usuario*/
#define DEVICE_NAME "crypto"           /* Nome do dispositivo que aparecera em /proc/devices (sera o nome do arquivo criado com mknode /dev/crypto c MAJOR 0) */
#define CLASS_NAME "cryptomodule"      /* Definicao da classe do dispositivo */

#define CIPHER_BLOCK_SIZE 16 		       /* tamanho do bloco para encriptacao */
#define KEY_SIZE 256
#define SHA256_LENGTH KEY_SIZE / 8

MODULE_LICENSE("GPL");                                               /* Tipo da licenca */
MODULE_AUTHOR("Projeto 1");                                          /* Autor */
MODULE_DESCRIPTION("Custom crypto driver - Encrypt, Decrypt, Hash"); /* Descricao do modulo */
MODULE_VERSION("1.0");                                               /* Varsao */

/* OBS: os prints estarao em /var/log/kernel.log ou dmesg
 * para imprimir tail kern.log
*/

/* estruturas para funcao de criptografia */
struct tcrypt_result {
	struct completion completion;
	int err;
};

struct skcipher_def {
	struct scatterlist sg;
	struct crypto_skcipher * tfm;
	struct skcipher_request * req;
	struct tcrypt_result result;
	char * scratchpad;
	char * ciphertext;
	char * ivdata;
	unsigned int encrypt;
};

/* Todas as variaveis globais devem ser ESTATICAS para evitar conflitos com as demais existentes na memoria do Kernel */
static int qtdBlocos;
static int majorNumber;                                 /* Armazena o numero major definido automaticamente pelo driver */
static int size_of_message;                             /* Guarda o tamanho da entrada quando o usuario grava alguma coisa no arquivo do modulo */
static int size_of_key;
static int size_of_output;
static char operacao;                                   /* Indica a operacao a ser realizada c - d - h */
static char *key;                                       /* Armazena a chave em CARACTERES passada como parametro na insercao do modulo -- Durante a conversao, o limite definido foi de 64 caracteres hexa de entrada ou seja, 32 bytes*/
static char keyHexa[(KEY_SIZE / 8) + 1];                      /* Armazena a chave HEXADECIMAL convertida a partir da chave em CARACTERES */
static char keyChar[(KEY_SIZE / 4) + 1];                  /* Representacao em caracteres da chave considerada em hexadecimal */
static char mensagemHexaInput[(KEY_SIZE / 8) * 5 + 1];  /* Armazena a mensagem lida do arquivo do modulo em forma hexadecimal para ser utilizado na criptografia, descriptografia ou hash obs: vezes 5 pois definimos que iremos realizar as operacoes com no maximo 5 blocos (160 bytes)*/
static char mensagemHexaOutput[(KEY_SIZE / 8) * 5 + 1]; /* Armazena o resultado da criptogragia, descriptografia ou hash em hexadecimal */
static char mensagemCharInput[(KEY_SIZE / 4) * 5 + 3];  /* Armazena a mensagem em CARACTERES lida do arquivo do modulo. Obs: o tamanho eh "ilimitado", mas iremos considerar os primeiros 64*5(blocos) caracteres*/
static char mensagemCharOutput[(KEY_SIZE / 4) * 5 + 1]; /* Armazena o resultado da criptogragia, descriptografia ou hash em CARACTERES, para imprimir no arquivo do modulo */
static int numUtil = 0;                                 /* Contador do numero de vezes que o arquivo de dispositivo foi aberto */
static struct device *cryptomoduleDevice = NULL;        /* Ponteiro para a struct do driver de dispositivo */
static struct class *cryptomoduleClass = NULL;          /* Ponteiro para a struct da classe representando o driver de dispositivo */
static struct skcipher_def sk;                          /* estrutura para funcao de encriptar */

/* Prototipos das funcoes */
static int      dev_abrir(struct inode *, struct file *);
static int      dev_fechar(struct inode *, struct file *);
static ssize_t  dev_leitura(struct file *, char *, size_t, loff_t *);
static ssize_t  dev_escrita(struct file *, const char *, size_t, loff_t *);
static void     converterChar2Hexa(char *pChar, char *pHexa);
static void     converterHexa2Char(char *pHexa, char *pChar);
static int      cryptosha256(char *pData, char *pResultado);
static void 	  test_skcipher_finish(struct skcipher_def * sk);
static int 	    test_skcipher_result(struct skcipher_def * sk, int rc);
static void 	  test_skcipher_callback(struct crypto_async_request *req, int error);
static int 	    test_skcipher_encrypt(char * plaintext, struct skcipher_def * sk);

/* Obtendo os parametros passados na inicializacao */
/* para carregar o modulo: insmod cryptomodule.ko key="ABCDEF12345667890" */
module_param(key, charp, 0000);
MODULE_PARM_DESC(key, "Chave recebida durante o carregamento");

/* Associacao de funcoes as operacoes de abertura, fechamento, leitura e escrita em um arquivo atraves da
 * estrutura de operacoes file_operations
 */
static struct file_operations fops ={
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
  size_of_key = strlen(key);
  if (size_of_key > 64) size_of_key=64;
  size_of_message = size_of_key;

  pr_info("cryptoModule: Chave (Key) BRUTA recebida: %s\n", key);
  converterChar2Hexa(key, keyHexa);     /* Salva em keyHexa a sequencia de bytes que representa os caracteres em hexadecimal lidos no carregamento do modulo */
	if(size_of_key % 2 != 0)
	{
		size_of_key += 1;
		size_of_message = size_of_key;
  }
  converterHexa2Char(keyHexa, keyChar); /* Salva em keyChar os caracteres que representam a chave em hexadecimal */
  pr_info("cryptoModule: Chave (Key) CONSIDERADA em hexadecimal: %s\n", keyChar);
  size_of_key /= 2;
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

  /* Para enviar os dados para o usuario, temos que converter os dados em hexadecimal mensagemHexaOutput para mensagemCharOutput */
  /* Para isso */
  converterHexa2Char(mensagemHexaOutput, mensagemCharOutput);

  /* A funcao copy_to_user retorna 0 quando eh sucedida, sua estrutura eh:
    * copy_to_user(ponteiro para onde, ponteiro de onde, tamanho em bytes)
    */
  contador_erro = copy_to_user(buffer, mensagemCharOutput, (KEY_SIZE/4)*5 + 1); /* estou copiando para buffer size_of_message bytes de message */

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
  /* resetando todas as variaveis */
  memset(mensagemCharInput,0,64*5);
  memset(mensagemCharOutput,0,64*5);
  memset(mensagemHexaInput,0,32*5);
  memset(mensagemHexaOutput,0,32*5);

  /* Convertendo o dado de entrada para hexa - Definimos no maximo 5 blocos de dados */
  /* Quebrando a mensagemCharInput em blocos de 32 bytes */
  /* Convertendo cada bloco de 64 caracteres para um de 32 bytes hexadecimal mensagemCharInput (64B) -> mensagemHexaInput(32B) */
  if(len > 322) len = 322;
  copy_from_user(mensagemCharInput,buffer,len);
  mensagemCharInput[len] = '\0';
  size_of_message = len-2;           // Armazena o tamanho da chave recebida
  sprintf(&operacao, "%c", mensagemCharInput[0]); // Pega a opcao de operacao
  strcpy(mensagemCharInput,mensagemCharInput+2);

  /* mensagemCharInput nao pode ser maior do que 64*5 caracteres, caso for, somente consideramos os 64*5 caracteres iniciais */
  if (size_of_message > 64 * 5)
    size_of_message = 64 * 5;

  qtdBlocos = size_of_message / 32;
	if(size_of_message % 32 != 0) qtdBlocos++;
  converterChar2Hexa(mensagemCharInput, mensagemHexaInput);
  converterHexa2Char(mensagemHexaInput, mensagemCharOutput);
  printk(KERN_INFO "cryptoModule: Recebeu do arquivo a operacao:%c e dado convertido para Hexa: %s", operacao, mensagemCharOutput);

  size_of_output = (qtdBlocos) * CIPHER_BLOCK_SIZE *2;

  /* Para as operacoes, a entrada sera a mensagemHexaInput e a saida devera obrigatoriamente estar contida em mensagemHexaOutput */
  switch (operacao)
  {
  case 'c': /* Aqui eh o codigo responsavel por Cifrar mensagemHexaInput e salvar os dados em mensagemHexaOutput */
    printk("cryptoModule: Cifrar\n");
    /* Inicializacao da funcao de encryptar */
    sk.tfm = NULL;
    sk.req = NULL;
    sk.scratchpad = NULL;
    sk.ciphertext = NULL;
    sk.ivdata = NULL;
    sk.encrypt = 1;                                        /* operacao: 1 para encriptar e 0 para decriptar */
    test_skcipher_encrypt(mensagemHexaInput, &sk);/* chamada de funcao (string para encriptar, chave, estrutura para encriptar) */
    test_skcipher_finish(&sk);                             /* funcao para retirar resultado do scatterlist */
    size_of_message = (qtdBlocos) * 32;
    break;

  case 'd': /* Aqui eh o codigo responsavel por Decifrar mensagemHexaInput e salvar o resultado em mensagemHexaOutput */
    printk("cryptoModule: Decifrar\n");
    /* Inicializacao da funcao de decryptar */
    sk.tfm = NULL;
    sk.req = NULL;
    sk.scratchpad = NULL;
    sk.ciphertext = NULL;
    sk.ivdata = NULL;
    sk.encrypt = 0;                                        /* operacao: 1 para encriptar e 0 para decriptar */
    test_skcipher_encrypt(mensagemHexaInput, &sk);/* chamada de funcao (string para encriptar, chave, estrutura para encriptar) */
    test_skcipher_finish(&sk);                             /* funcao para retirar resultado do scatterlist */
    size_of_message = (qtdBlocos) * 32;
		size_of_output = (qtdBlocos) * CIPHER_BLOCK_SIZE;
    break;

  case 'h': /* Aqui eh o codigo responsavel por Calcular o hash da mensagemHexaInput e salvar em mensagemHexaOutput*/
    /* em tese, um hash nao possui limite de entrada, porem, nesse modulo, ela foi limitada a 64*5=320 caracteres */
    printk("cryptoModule: Calcular Hash\n");
    cryptosha256(mensagemHexaInput, mensagemHexaOutput); /* Aqui size_of_message contem quantos caracteres o mensagemHexaInput possui convertidos para hexadecimal */
    size_of_output = 64; /* A saida do hash eh sempre de mesmo tamanho */
    size_of_message=64;
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
static void converterChar2Hexa(char *pChar, char *pHexa)
{
  /* Ideia: Cada byte de pchar sera convertido em dois digitos hexa em cada posicao de pHexa, ou seja, o tamanho de pchar eh o dobro de phexa */
  /* o Padding sera feito na direita */
  int i;
  int j=0;
  /* Zerando o conteudo da memoria do array keyHexa -> Garante que nao existira lixo na memoria */
  /* Seta todas as posicoes com 0 -- size_of_messagesera OBRIGATORIAMENTE PAR, ja que cada digito hexa correspondem a dois numeros */
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

}

/* Funcao para converter um array de hexadecimais para uma string de caracteres */
static void converterHexa2Char(char *pHexa, char *pChar)
{
  int i;
  for (i = 0; i < size_of_message/2; i++)
  {
    sprintf(&pChar[i * 2], "%02hhx", (unsigned char)pHexa[i]);
  }
  pChar[i*2] = '\0';

}

static int cryptosha256(char *pData, char *pResultado)
{

    char *plaintext;                 /* String no qual o hash sera feito */
    char hash_sha256[SHA256_LENGTH]; /* String contendo o resultado da operacao hash */
    struct crypto_shash *sha256;     /* Objeto de transformacao da api do hash -> uma struct que armazena os dados da operacao hash */
    struct shash_desc *shash;        /* Struct com o objeto de transformacao e flags do hash */
    int qtdBytes = (size_of_message % 2 == 0) ? (qtdBytes=size_of_message) : (qtdBytes=size_of_message+1);

    plaintext = (char *)vmalloc(size_of_message/2);
    strcpy(plaintext,pData);

    sha256 = crypto_alloc_shash("sha256", 0, 0); /* Indica que o hash feito sera o SHA256 */

    if (IS_ERR(sha256)) /* Caso a indicacao acima de erro retorna -1 */
        return -1;

    shash = vmalloc(sizeof(struct shash_desc) + crypto_shash_descsize(sha256)); /* Aloca espaco para a struct que contem o TFM (objeto de transformacao) e flags do hash */

    if (!shash) /* Caso nao exista memoria disponivel ou nao consegui alocar espaco retorna um erro */
        return -ENOMEM;

    shash->tfm = sha256; /* Seta o objeto de tranformacao para SHA256 */
    shash->flags = 0;    /* Flags com valor 0 */

    if (crypto_shash_init(shash)) /* Inicializa a operacao de hash */
        return -1;

    if (crypto_shash_update(shash, plaintext, strlen(plaintext))) /* Realiza o HASH sobre plaintext */
        return -1;

    if (crypto_shash_final(shash, hash_sha256)) /* Termina o Hash */
        return -1;

    vfree(shash);                             /* Desaloca a estrturura alocada dinamicamente para realizar o hash */
    vfree(plaintext);
    crypto_free_shash(sha256);                /* Libera o objeto de hash sha256 */
    memcpy(pResultado,hash_sha256,32);        /* Copia o resultado do hash para mensagemHexaOutput */

    return 0;
}

static void test_skcipher_finish(struct skcipher_def * sk) /* função de desalocação das memorias utilizadas */
{
	if (sk->tfm)
		crypto_free_skcipher(sk->tfm);   /* desaloca o algoritimo de transformacao */
	if (sk->req)
		skcipher_request_free(sk->req);  /* desaloca os dados de requisicao para a encriptacao */

  /*ivdata: vetor de inicializacao, variavel a ser utilizada em conjunto com a chave de encryptação para evitar q a string de saida tenha partes parecidas,
            isso evita q algum terceiro analise algum padrao gerado tornando a encrytacao mais segura, nao eh necessario ter o ivdata para decryptar mas caso for possivel
            ter a chave e o ivdata a encryptacao eh mais rapida
  */
	if (sk->ivdata)
		vfree(sk->ivdata);      /* libebra o vetor de inicializacao */
	if (sk->scratchpad)
		vfree(sk->scratchpad);  /* desaloca o espaco aonde ira a entrada antes de ser passada para a scatterlist */
	if (sk->ciphertext)
		vfree(sk->ciphertext);  /* desaloca o espaco aonde ira a saida da funcao de decriptar */
}

static int test_skcipher_result(struct skcipher_def * sk, int rc) /* testa o retorna da encriptacao */
{
	switch (rc)
  {
		case 0:              /* caso for 0 encriptacao terminou sem erros */
			break;
	  case -EINPROGRESS: /* caso contrario trata o erro retornado */
	  case -EBUSY:
		  rc = wait_for_completion_interruptible(&sk->result.completion);
		  if (!rc && !sk->result.err)
      {
  			reinit_completion(&sk->result.completion);
  			break;
		  }
	  default:
		  printk("cryptoModule: skcipher encrypt retornou com %d resultado %d\n", rc, sk->result.err);
		break;
	}

	init_completion(&sk->result.completion); /* caso n tiver erros termina encrytacao */
	return rc;
}

static void test_skcipher_callback(struct crypto_async_request *req, int error) /* funcao de callback, chamada quando o crypto termina */
{
	struct tcrypt_result *result = req->data; /* estrutura result para funcao complete() */
	if (error == -EINPROGRESS)                /* caso a funcao estiver executando ainda, retornar e esperar ate terminar */
		return;
	result->err = error;                      /* atribui erro da funcao do crypto */
	complete(&result->completion);            /* completar a funcao de cryto de acordo com seu erro, caso n tiver termina normalmente */
	printk("cryptoModule: Criptografia terminada com sucesso\n");
}

/* argumentos: plaintext -> conteudo a ser encryptado; password -> chave de encryptacao; sk -> estrutura com todas as informacoes necessarias para a encryptacao */
static int test_skcipher_encrypt(char * plaintext, struct skcipher_def * sk) /* funcao "pai" de criptografia */
{
  int j;
	int ret = -EFAULT;                                         /* retorno da funcao */
	if (!sk->tfm)                                              /* aloca variavel de algoritimo de transformacao */
  {
		sk->tfm = crypto_alloc_skcipher("ecb-aes-aesni", 0, 0);  /* definindo o algoritimo aes, ecb */
		if (IS_ERR(sk->tfm))                                     /* caso erro na alocacao do objeto de tranformacao */
    {
			printk("cryptoModule: Nao foi possivel alocar o objeto de transformacao\n");
			return PTR_ERR(sk->tfm);
		}
	}
	if (!sk->req)   /* aloca variavel req, req contem todas as informacoes necessarias para fazer uma requisicao de encryptacao */
  {
		sk->req = skcipher_request_alloc(sk->tfm, GFP_KERNEL);
		if (!sk->req) /* caso falha na alocacao impirme mensagem de erro*/
    {
			printk("cryptoModule: Nao foi possivel alocar o request\n");
			ret = -ENOMEM;
			return ret;
		}
	}

  /* direciona qual a funcao de callback ao terminar o request de encryptacao */
	skcipher_request_set_callback(sk->req, CRYPTO_TFM_REQ_MAY_BACKLOG,test_skcipher_callback,&sk->result);

	/* atrelando chave ao algoritimo de transformacao AES 256*/
	if (crypto_skcipher_setkey(sk->tfm, keyHexa, KEY_SIZE/8)) {
		printk("cryptoModule: Nao foi possivel atrelar a chave ao algoritmo de tranformacao\n");
		ret = -EAGAIN;
		return ret;
	}

	if (!sk->ivdata) { /* aloca iv data aleatorio */
		/* mais info https://en.wikipedia.org/wiki/Initialization_vector */
		sk->ivdata = vmalloc(CIPHER_BLOCK_SIZE);
		if (!sk->ivdata) {
			printk("cryptoModule: Nao foi possivel alocar ivDATA\n");
			return ret;
		}
		get_random_bytes(sk->ivdata, CIPHER_BLOCK_SIZE);
	}

	if (!sk->scratchpad) { /* alocar variavel para texto a ser criptografado */
		sk->scratchpad = vmalloc(CIPHER_BLOCK_SIZE);
		if (!sk->scratchpad) {
			printk("cryptoModule: Nao foi possivel alocar o Scratchpad\n");
			return ret;
		}
	}

  printk("qtdBlocos: %i",qtdBlocos);
  for(j=0; j< qtdBlocos; j++)
  {
    memcpy(sk->scratchpad,plaintext+CIPHER_BLOCK_SIZE*j,CIPHER_BLOCK_SIZE);
    sg_init_one(&sk->sg, sk->scratchpad, CIPHER_BLOCK_SIZE); //inicializar text na scatterlist
  	skcipher_request_set_crypt(sk->req, &sk->sg, &sk->sg,	CIPHER_BLOCK_SIZE, sk->ivdata); //especifica qual as variaveis para encriptacao
    //request com todos os dados para encriptar, fonte dos dados a ser encriptado, destino dos dados a ser encriptado, tamanho do bloco, ivdata
  	init_completion(&sk->result.completion); //iniciar criptogragia

  	if (sk->encrypt) { //caso a variavel encrypt for 1 encriptar
  		ret = crypto_skcipher_encrypt(sk->req);
  	} else { //caso a variavel encrypt for 0 decriptar
  		ret = crypto_skcipher_decrypt(sk->req);
  	}

  	ret = test_skcipher_result(sk, ret);//testar resultado da encriptacao

  	if (ret)
  		return ret;

    sk->ciphertext = sg_virt(&(sk->sg));//ponteiro da scatterlist para variavel ciphertext
    memcpy(mensagemHexaOutput+CIPHER_BLOCK_SIZE*j,sk->scratchpad,CIPHER_BLOCK_SIZE);
  	sk->ciphertext = NULL;//zera variavel ciphertext para n dar erro na funcao finish
  }

 	return ret;
}
/* Inicializacao das funcoes de init e exit, ja que ambas foram criadas com macros */
module_init(cryptomodule_init);
module_exit(cryptomodule_exit);
